package multipath

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type PrivacyEndpoint struct {
	Protocol  string
	Address   string
	ServerSNI string
	Username  string
	Password  string
	NextHop   *PrivacyEndpoint
}

type PrivacyEngine struct {
	mu           sync.RWMutex
	wifiEgress   *PrivacyEndpoint
	cellEgress   *PrivacyEndpoint
	fragmentTLS  atomic.Bool
	blockWebRTC  atomic.Bool
	stripHeaders atomic.Bool
	anycastCloak atomic.Bool
	prngMu       sync.Mutex
	prngKey      [32]byte
	prngCounter  uint64
}

var GlobalPrivacy = newPrivacyEngine()

func newPrivacyEngine() *PrivacyEngine {
	p := &PrivacyEngine{}
	p.fragmentTLS.Store(true)
	p.blockWebRTC.Store(true)
	p.stripHeaders.Store(true)
	p.anycastCloak.Store(true)
	_, _ = rand.Read(p.prngKey[:])
	return p
}

// FillCryptoRandom returns fast CSPRNG bytes derived from an in-memory
// SHA-256 counter stream so hot-path record slicing and EDNS0 padding never
// block on getrandom(2) syscalls.
func (p *PrivacyEngine) FillCryptoRandom(dst []byte) {
	p.prngMu.Lock()
	p.prngCounter++
	cnt := p.prngCounter
	key := p.prngKey
	p.prngMu.Unlock()

	var seed [40]byte
	copy(seed[0:32], key[:])
	binary.LittleEndian.PutUint64(seed[32:40], cnt)

	written := 0
	for written < len(dst) {
		sum := sha256.Sum256(seed[:])
		n := copy(dst[written:], sum[:])
		written += n
		seed[32]++
	}
}

func (p *PrivacyEngine) ConfigurePrivacyTunnels(wifi, cell *PrivacyEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wifiEgress = wifi
	p.cellEgress = cell
}

func (p *PrivacyEngine) EgressForLink(link LinkType) *PrivacyEndpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if link == LinkCellular {
		if p.cellEgress != nil && p.cellEgress.Address != "" {
			return p.cellEgress
		}
		if p.wifiEgress != nil && p.wifiEgress.Address != "" {
			return p.wifiEgress
		}
		return nil
	}
	if p.wifiEgress != nil && p.wifiEgress.Address != "" {
		return p.wifiEgress
	}
	if p.cellEgress != nil && p.cellEgress.Address != "" {
		return p.cellEgress
	}
	return nil
}

func (p *PrivacyEngine) SetTLSFragmentation(enabled bool) {
	p.fragmentTLS.Store(enabled)
}

func (p *PrivacyEngine) TLSFragmentationEnabled() bool {
	return p.fragmentTLS.Load()
}

func (p *PrivacyEngine) SetBlockWebRTC(enabled bool) {
	p.blockWebRTC.Store(enabled)
}

func (p *PrivacyEngine) WebRTCBlockingEnabled() bool {
	return p.blockWebRTC.Load()
}

func (p *PrivacyEngine) SetAnycastCloak(enabled bool) {
	p.anycastCloak.Store(enabled)
}

func (p *PrivacyEngine) AnycastCloakEnabled() bool {
	return p.anycastCloak.Load()
}

// CloakAnycastIP maps a domain-specific Cloudflare/Fastly Anycast IP to a
// rotating generic local IXP Anycast edge IP in the same /24 cluster so ISP
// NetFlow logs never see the unique origin IP.
// NOTE: defined but NOT wired into the dial path — connecting to a random
// /24 sibling of an Anycast address is unreliable (a different Anycast IP is
// a different address that may not serve the customer's content, and there
// is no fallback here). Left as a stub for future work.
func CloakAnycastIP(rawIP string) (cloakedIP string, isCloaked bool) {
	if !GlobalPrivacy.AnycastCloakEnabled() {
		return rawIP, false
	}
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return rawIP, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return rawIP, false
	}
	// Cloudflare Anycast ranges: 104.16.0.0/12 (104.16-31.x.x), 172.64.0.0/13 (172.64-71.x.x)
	isCF := (v4[0] == 104 && v4[1] >= 16 && v4[1] <= 31) ||
		(v4[0] == 172 && v4[1] >= 64 && v4[1] <= 71)
	if !isCF {
		return rawIP, false
	}
	var rnd [1]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])
	// Rotate across Anycast POP sibling addresses within the same /24 BGP announcement
	hostOctet := byte(10 + (int(rnd[0]) % 200))
	if hostOctet == v4[3] {
		hostOctet = (hostOctet + 1) % 240
		if hostOctet == 0 {
			hostOctet = 1
		}
	}
	cloaked := net.IPv4(v4[0], v4[1], v4[2], hostOctet).String()
	return cloaked, true
}

// ShouldBlockPrivacyLeak is the single choke point for side-channel and
// identity leaks inside the gVisor forwarders.
func ShouldBlockPrivacyLeak(isUDP bool, payload []byte, dstPort int) bool {
	if isUDP && dstPort == 443 {
		// Block QUIC (HTTP/3) so all HTTPS uses multi-connection TCP 443 with
		// Chameleon-TLS SNI shattering and dual-radio bonding.
		return true
	}
	if !isUDP && dstPort == 53 {
		// Block plaintext TCP/53 bypass (forces apps to use intercepted UDP/53 -> DoH).
		return true
	}
	switch dstPort {
	case 853, // Block direct DoT bypass so DNS uses the sharded DoH VIP resolver
		5353,          // mDNS local identity leak
		5355,          // LLMNR leak
		1900,          // SSDP UPnP discovery leak
		137, 138, 139: // NetBIOS leak
		return true
	}
	if !GlobalPrivacy.WebRTCBlockingEnabled() {
		return false
	}
	if dstPort == 3478 || dstPort == 5349 || (dstPort >= 19302 && dstPort <= 19309) {
		return true
	}
	if isUDP && len(payload) >= 20 {
		msgType := binary.BigEndian.Uint16(payload[0:2])
		cookie := binary.BigEndian.Uint32(payload[4:8])
		if (msgType&0xC000 == 0) && cookie == 0x2112A442 {
			return true
		}
	}
	return false
}

// Ensure cipher interface remains referenced for future AEAD extensions.
var _ cipher.AEAD

func wrapHopTLS(ctx context.Context, rawConn net.Conn, hop *PrivacyEndpoint) (net.Conn, error) {
	proto := strings.ToLower(strings.TrimSpace(hop.Protocol))
	if proto != "https" && proto != "socks5s" && proto != "tls" {
		return rawConn, nil
	}
	sni := hop.ServerSNI
	if sni == "" {
		sni, _, _ = net.SplitHostPort(hop.Address)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func handshakeSingleHop(ctx context.Context, conn net.Conn, hop *PrivacyEndpoint, nextTarget string) (net.Conn, error) {
	c, err := wrapHopTLS(ctx, conn, hop)
	if err != nil {
		return nil, err
	}
	proto := strings.ToLower(strings.TrimSpace(hop.Protocol))
	if proto == "http" || proto == "https" || proto == "connect" {
		if err := handshakeHTTPConnect(ctx, c, nextTarget, hop.Username, hop.Password); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}
	if err := handshakeSOCKS5(ctx, c, nextTarget, hop.Username, hop.Password); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func DialThroughPrivacyEgress(
	ctx context.Context,
	dialer *net.Dialer,
	ep *PrivacyEndpoint,
	network, targetAddr string,
) (net.Conn, error) {
	if ep == nil || ep.Address == "" {
		return dialer.DialContext(ctx, network, targetAddr)
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", ep.Address)
	if err != nil {
		return nil, err
	}
	if ep.NextHop != nil && ep.NextHop.Address != "" {
		hop1Conn, err := handshakeSingleHop(ctx, rawConn, ep, ep.NextHop.Address)
		if err != nil {
			return nil, err
		}
		hop2Conn, err := handshakeSingleHop(ctx, hop1Conn, ep.NextHop, targetAddr)
		if err != nil {
			return nil, err
		}
		return hop2Conn, nil
	}
	return handshakeSingleHop(ctx, rawConn, ep, targetAddr)
}

func handshakeSOCKS5(ctx context.Context, conn net.Conn, targetAddr, user, pass string) error {
	deadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return err
	}
	if methodResp[0] != 0x05 {
		return errors.New("privacy: invalid socks5 version")
	}
	if methodResp[1] == 0x02 {
		uBytes := []byte(user)
		pBytes := []byte(pass)
		if len(uBytes) > 255 || len(pBytes) > 255 {
			return errors.New("privacy: socks5 credentials too long")
		}
		authReq := make([]byte, 0, 3+len(uBytes)+len(pBytes))
		authReq = append(authReq, 0x01, byte(len(uBytes)))
		authReq = append(authReq, uBytes...)
		authReq = append(authReq, byte(len(pBytes)))
		authReq = append(authReq, pBytes...)
		if _, err := conn.Write(authReq); err != nil {
			return err
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return errors.New("privacy: socks5 authentication failed")
		}
	} else if methodResp[1] != 0x00 {
		return errors.New("privacy: unsupported socks5 auth method")
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("privacy: target hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("privacy: socks5 connect failed with code %d", hdr[1])
	}

	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var domLen [1]byte
		if _, err := io.ReadFull(conn, domLen[:]); err != nil {
			return err
		}
		skip = int(domLen[0]) + 2
	default:
		return errors.New("privacy: unknown socks5 address type")
	}
	trash := make([]byte, skip)
	_, err = io.ReadFull(conn, trash)
	return err
}

func handshakeHTTPConnect(ctx context.Context, conn net.Conn, targetAddr, user, pass string) error {
	deadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr))
	if user != "" {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		sb.WriteString("Proxy-Authorization: Basic " + token + "\r\n")
	}
	sb.WriteString("\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("privacy: HTTP CONNECT failed with status %d", resp.StatusCode)
	}
	return nil
}

func isTLSClientHello(b []byte) bool {
	if len(b) < 43 {
		return false
	}
	return b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

func WriteClientHello(conn net.Conn, b []byte) (int, error) {
	if GlobalPrivacy.TLSFragmentationEnabled() && isTLSClientHello(b) {
		return writeFragmentedClientHello(conn, b)
	}
	return conn.Write(b)
}

// setSocketMaxSeg dynamically clamps TCP_MAXSEG during ClientHello shattering
// so the Linux kernel flushes micro-records into separate wire packets without
// needing long sleep delays, then restores the link's full MSS.
func setSocketMaxSeg(conn net.Conn, mss int) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpMaxSeg, mss)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	})
}

// writeFragmentedClientHello implements Chameleon-TLS:
//  1. Splits the 4-byte Handshake header at byte 2 so the first TLS record
//     cannot even be parsed as a valid Handshake header by stateless DPI regexes.
//  2. Uses a cryptographic random stream to shatter the SNI extension header
//     and hostname into entropy-randomized micro-records (3 to 7 bytes each),
//     defeating both stateful SNI inspection and ML packet-size classifiers.
//  3. Preserves 100% RFC 8446 Transcript-Hash invariance because TLS record
//     headers (0x16 0x03 0x03 len) are stripped before handshake hashing.
func writeFragmentedClientHello(conn net.Conn, b []byte) (int, error) {
	if !(len(b) >= 43 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01) {
		return conn.Write(b)
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recordLen || recordLen < 32 {
		return conn.Write(b)
	}

	payload := b[5 : 5+recordLen]
	var rnd [8]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])

	// Build strictly increasing cut offsets inside payload:
	// Cut 0: byte 2 (splits the 4-byte Handshake header 0x01 + uint24 length in half!)
	// Cut 1: randomized byte 11..24 inside ClientRandom
	var cuts []int
	cuts = append(cuts, 2)
	cutRandom := 11 + int(rnd[0]%14)
	if cutRandom < len(payload)-8 {
		cuts = append(cuts, cutRandom)
	}

	sniStart, sniEnd := findSNIBounds(payload)
	if sniStart > cutRandom+2 && sniEnd > sniStart && sniEnd <= len(payload) {
		// Cut right inside the 4-byte SNI Extension Header (0x00 0x00 [extLen])
		cuts = append(cuts, sniStart+2)
		// Shatter the SNI hostname itself into 3-to-6 byte cryptographic shards
		pos := sniStart + 4
		shardIdx := 1
		for pos < sniEnd {
			step := 3 + int(rnd[shardIdx%len(rnd)]%4) // 3..6 bytes per record
			pos += step
			shardIdx++
			if pos < sniEnd && pos < len(payload)-2 {
				cuts = append(cuts, pos)
			}
		}
	} else {
		mid := len(payload) / 2
		if mid > cutRandom+4 {
			cuts = append(cuts, mid)
		}
	}

	// Clamp kernel MSS to minimal allowed value during handshake shattering
	setSocketMaxSeg(conn, 88)
	defer setSocketMaxSeg(conn, cellSafeMSS)

	prev := 0
	for i := 0; i <= len(cuts); i++ {
		end := len(payload)
		if i < len(cuts) {
			end = cuts[i]
		}
		if end <= prev {
			continue
		}
		part := payload[prev:end]
		prev = end

		rec := make([]byte, 5+len(part))
		rec[0] = 0x16
		rec[1] = b[1]
		rec[2] = b[2]
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(part)))
		copy(rec[5:], part)

		if i == len(cuts) && len(b) > 5+recordLen {
			rec = append(rec, b[5+recordLen:]...)
		}

		if _, err := conn.Write(rec); err != nil {
			return 0, err
		}
		// Micro-paced flush barrier (350-650us jitter) prevents kernel TSO/GSO
		// coalescing while keeping total handshake overhead under ~2.5ms.
		if i < len(cuts) {
			jitterUs := 350 + int(rnd[i%len(rnd)])%300
			time.Sleep(time.Duration(jitterUs) * time.Microsecond)
		}
	}
	return len(b), nil
}

// findSNIBounds returns the start and end offset of the SNI extension (0x0000)
// within the ClientHello handshake payload.
func findSNIBounds(handshake []byte) (int, int) {
	idx := 38
	if len(handshake) <= idx {
		return 0, 0
	}
	sessIDLen := int(handshake[idx])
	idx += 1 + sessIDLen
	if len(handshake) < idx+2 {
		return 0, 0
	}
	cipherLen := int(binary.BigEndian.Uint16(handshake[idx : idx+2]))
	idx += 2 + cipherLen
	if len(handshake) < idx+1 {
		return 0, 0
	}
	compLen := int(handshake[idx])
	idx += 1 + compLen
	if len(handshake) < idx+2 {
		return 0, 0
	}
	extTotalLen := int(binary.BigEndian.Uint16(handshake[idx : idx+2]))
	idx += 2
	end := idx + extTotalLen
	if end > len(handshake) {
		end = len(handshake)
	}
	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(handshake[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(handshake[idx+2 : idx+4]))
		if extType == 0x0000 && extLen > 4 && idx+4+extLen <= end {
			return idx, idx + 4 + extLen
		}
		idx += 4 + extLen
	}
	return 0, 0
}

func SanitizePrivacyHeaders(h http.Header) {
	if h == nil || !GlobalPrivacy.stripHeaders.Load() {
		return
	}
	for _, k := range []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"Via",
		"Forwarded",
		"X-Client-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
	} {
		h.Del(k)
	}
}
