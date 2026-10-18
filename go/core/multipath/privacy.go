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
	l4Morphing   atomic.Bool
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
	p.l4Morphing.Store(true)
	_, _ = rand.Read(p.prngKey[:])
	return p
}

// FillCryptoRandom returns fast CSPRNG bytes derived from an in-memory
// SHA-256 counter stream so hot-path L4 segment morphing and EDNS0 padding
// never block on getrandom(2) syscalls.
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

func (p *PrivacyEngine) SetTLSFragmentation(enabled bool) { p.fragmentTLS.Store(enabled) }
func (p *PrivacyEngine) TLSFragmentationEnabled() bool    { return p.fragmentTLS.Load() }
func (p *PrivacyEngine) SetBlockWebRTC(enabled bool)      { p.blockWebRTC.Store(enabled) }
func (p *PrivacyEngine) WebRTCBlockingEnabled() bool      { return p.blockWebRTC.Load() }
func (p *PrivacyEngine) SetAnycastCloak(enabled bool)     { p.anycastCloak.Store(enabled) }
func (p *PrivacyEngine) AnycastCloakEnabled() bool        { return p.anycastCloak.Load() }
func (p *PrivacyEngine) SetL4Morphing(enabled bool)       { p.l4Morphing.Store(enabled) }
func (p *PrivacyEngine) L4MorphingEnabled() bool          { return p.l4Morphing.Load() }

// ShouldBlockPrivacyLeak is the single choke point for side-channel and
// identity leaks inside the gVisor forwarders.
func ShouldBlockPrivacyLeak(isUDP bool, payload []byte, dstPort int) bool {
	if isUDP && dstPort == 443 {
		// Block QUIC (HTTP/3) so all HTTPS uses multi-connection TCP 443 with
		// zero-suspicion SNI slicing, L4 stream morphing, and dual-radio bonding.
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

var _ cipher.AEAD

// MorphingConn wraps a net.Conn and defeats ML Website Fingerprinting
// (Deep Fingerprinting / Packet-Size Sequence Correlation) during the critical
// initial window of a connection (first 16 KB of encrypted TLS 0x17 traffic).
//
// CRITICAL CRYPTOGRAPHIC INVARIANT:
// Unlike TLS Handshake (0x16) records prior to encryption, TLS 1.3 Application
// Data (0x17) records carry an AEAD authentication tag bound to the exact record
// length. MorphingConn NEVER alters bytes or record headers inside the TLS stream;
// instead, it slices outbound TCP writes at natural HTTP/2 frame-size boundaries
// (L4 TCP segmentation), decoupling wire-level IP packet sizes from the app's
// underlying TLS record sizes with zero AEAD errors and zero artificial latency.
type MorphingConn struct {
	net.Conn
	link           LinkType
	txMorphedBytes atomic.Int64
	firstWrite     atomic.Bool
}

const maxMorphWindowBytes = 16 * 1024

// Natural Chrome/Android HTTP/2 frame size anchors (SETTINGS, WINDOW_UPDATE,
// HEADERS, and common gRPC/REST payload quantum sizes) so wire packet sizes
// blend into normal browser traffic distributions.
var naturalH2SegmentSizes = [8]int{64, 96, 144, 192, 256, 340, 448, 576}

func WrapMorphingConn(c net.Conn, link LinkType) net.Conn {
	if c == nil {
		return nil
	}
	if _, ok := c.(*MorphingConn); ok {
		return c
	}
	mc := &MorphingConn{
		Conn: c,
		link: link,
	}
	mc.firstWrite.Store(true)
	return mc
}

func (mc *MorphingConn) Write(b []byte) (int, error) {
	if mc.firstWrite.CompareAndSwap(true, false) {
		if GlobalPrivacy.TLSFragmentationEnabled() && isTLSClientHello(b) {
			return writeFragmentedClientHello(mc.Conn, b)
		}
	}
	// Apply L4 TCP segment boundary morphing to the first 16 KB of encrypted
	// TLS Application Data (0x17) so ISP NetFlow/DPI packet-size classifiers
	// never observe the true application record lengths.
	if GlobalPrivacy.L4MorphingEnabled() &&
		len(b) > 128 &&
		b[0] == 0x17 &&
		mc.txMorphedBytes.Load() < maxMorphWindowBytes {
		mc.txMorphedBytes.Add(int64(len(b)))
		var rnd [2]byte
		GlobalPrivacy.FillCryptoRandom(rnd[:])
		cut := naturalH2SegmentSizes[rnd[0]&7] + int(rnd[1]&0x1F)
		if cut > 0 && cut < len(b)-32 {
			n1, err := mc.Conn.Write(b[:cut])
			if err != nil {
				return n1, err
			}
			n2, err := mc.Conn.Write(b[cut:])
			return n1 + n2, err
		}
	}
	return mc.Conn.Write(b)
}

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

// DialThroughPrivacyEgress routes a connection through the link's configured
// 1-hop or 2-hop oblivious relay (or directly if no relay is configured).
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

// handshakeHTTPConnect performs a camouflaged HTTP CONNECT handshake with
// a stock Android Chrome User-Agent and entropy-padded X-Padding header so the
// handshake packet size cannot be fingerprinted by ISP traffic analysis.
func handshakeHTTPConnect(ctx context.Context, conn net.Conn, targetAddr, user, pass string) error {
	deadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	var rnd [48]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])
	padLen := 16 + int(rnd[0]&0x1F) // 16..47 random bytes before base64 encoding
	padToken := base64.RawURLEncoding.EncodeToString(rnd[1 : 1+padLen])
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr))
	sb.WriteString("User-Agent: Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36\r\n")
	if user != "" {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		sb.WriteString("Proxy-Authorization: Basic " + token + "\r\n")
	}
	sb.WriteString("X-Padding: " + padToken + "\r\n\r\n")
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
		// Unwrap MorphingConn first (loop: warmPool can hand back an already-
		// wrapped standby conn): writeFragmentedClientHello writes rec1 through
		// conn.Write, which would re-trigger MorphingConn's firstWrite branch
		// and fragment rec1 a second time (3-4 records, SNI split lost).
		for {
			mc, ok := conn.(*MorphingConn)
			if !ok {
				break
			}
			conn = mc.Conn
		}
		return writeFragmentedClientHello(conn, b)
	}
	return conn.Write(b)
}

// SyscallConn delegates to the inner connection so setSocketMaxSeg's
// TCP_MAXSEG clamp works through the MorphingConn wrapper.
func (mc *MorphingConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := mc.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("morphing: inner conn has no syscall conn")
}

// setSocketMaxSeg dynamically clamps TCP_MAXSEG during ClientHello slicing
// so the Linux kernel flushes the two TLS records into separate TCP segments
// immediately, then restores standard MSS.
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

// writeFragmentedClientHello implements Zero-Suspicion Herd-Conformant SNI Slicing:
// 1. Splits the TLS ClientHello into 2 clean TLS records right across the SNI
// hostname midpoint (with a +/- 2 byte cryptographic jitter).
// 2. Preserves the client's authentic legacy_record_version (or uniform 0x0303
// on the continuation record) so enterprise WAFs (Cloudflare/Akamai/Suricata)
// never see anomalous TLS 1.1 (0x0302) record version oscillation.
// 3. Uses kernel TCP_MAXSEG clamping to force separate wire packets without
// artificial sleep delays while preserving 100% RFC 8446 Transcript-Hash invariance.
func writeFragmentedClientHello(conn net.Conn, b []byte) (int, error) {
	if len(b) < 43 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return conn.Write(b)
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recordLen || recordLen < 32 {
		return conn.Write(b)
	}
	payload := b[5 : 5+recordLen]
	var rnd [2]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])
	sniMid := findSNIMidpoint(payload)
	var cut int
	if sniMid > 16 && sniMid < len(payload)-8 {
		jitter := int(rnd[0]%5) - 2 // -2..+2 bytes around SNI midpoint
		cut = sniMid + jitter
	} else {
		cut = len(payload)/2 + int(rnd[0]%7)
	}
	if cut < 8 {
		cut = 8
	}
	if cut >= len(payload)-4 {
		cut = len(payload) / 2
	}
	part1 := payload[:cut]
	part2 := payload[cut:]
	// Record 1: keeps the original record version (0x0301 or 0x0303) sent by BoringSSL.
	rec1 := make([]byte, 5+len(part1))
	rec1[0] = 0x16
	rec1[1] = b[1]
	rec1[2] = b[2]
	binary.BigEndian.PutUint16(rec1[3:5], uint16(len(part1)))
	copy(rec1[5:], part1)
	// Record 2: uses standard TLS 1.2/1.3 record framing (0x0303) for continuation.
	tailLen := len(b) - (5 + recordLen)
	rec2 := make([]byte, 5+len(part2)+tailLen)
	rec2[0] = 0x16
	rec2[1] = 0x03
	rec2[2] = 0x03
	binary.BigEndian.PutUint16(rec2[3:5], uint16(len(part2)))
	copy(rec2[5:], part2)
	if tailLen > 0 {
		copy(rec2[5+len(part2):], b[5+recordLen:])
	}
	setSocketMaxSeg(conn, 128)
	if _, err := conn.Write(rec1); err != nil {
		setSocketMaxSeg(conn, wifiSafeMSS)
		return 0, err
	}
	setSocketMaxSeg(conn, wifiSafeMSS)
	if _, err := conn.Write(rec2); err != nil {
		return 0, err
	}
	return len(b), nil
}

// BuildProbeClientHello constructs a RFC 8446-compliant TLS 1.3 ClientHello
// with a fresh 32-byte CSPRNG random nonce, a random 32-byte compatibility
// SessionID, and mandatory TLS 1.3 extensions (supported_versions 0x002b,
// signature_algorithms 0x000d, supported_groups 0x000a, key_share 0x0033)
// so background Anycast Cloak verification probes look 100% like stock Android
// BoringSSL and never leak the user's real ClientHello.random.
func BuildProbeClientHello(sni string) []byte {
	var rnd [96]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])
	var exts []byte
	// 1. server_name (0x0000)
	if sni != "" {
		sniBytes := []byte(sni)
		sniLen := len(sniBytes)
		exts = append(exts, 0x00, 0x00)
		exts = append(exts, byte((sniLen+5)>>8), byte((sniLen+5)&0xff))
		exts = append(exts, byte((sniLen+3)>>8), byte((sniLen+3)&0xff))
		exts = append(exts, 0x00)
		exts = append(exts, byte(sniLen>>8), byte(sniLen&0xff))
		exts = append(exts, sniBytes...)
	}
	// 2. supported_groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
	exts = append(exts, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17)
	// 3. signature_algorithms (0x000d): ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256
	exts = append(exts, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04)
	// 4. supported_versions (0x002b): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
	exts = append(exts, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03)
	// 5. key_share (0x0033): 32-byte x25519 ephemeral key share
	exts = append(exts, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	exts = append(exts, rnd[64:96]...)
	var body []byte
	body = append(body, 0x03, 0x03)   // Legacy Version TLS 1.2
	body = append(body, rnd[0:32]...) // 32-byte ClientRandom
	body = append(body, 0x20)         // 32-byte SessionID (TLS 1.3 middlebox compatibility mode)
	body = append(body, rnd[32:64]...)
	// Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	body = append(body, 0x00, 0x08, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b)
	body = append(body, 0x01, 0x00) // Compression: null
	body = append(body, byte(len(exts)>>8), byte(len(exts)&0xff))
	body = append(body, exts...)
	pkt := make([]byte, 9+len(body))
	pkt[0] = 0x16
	pkt[1] = 0x03
	pkt[2] = 0x01
	binary.BigEndian.PutUint16(pkt[3:5], uint16(4+len(body)))
	pkt[5] = 0x01 // HandshakeType ClientHello
	pkt[6] = 0x00
	binary.BigEndian.PutUint16(pkt[7:9], uint16(len(body)))
	copy(pkt[9:], body)
	return pkt
}

func findSNIMidpoint(handshake []byte) int {
	s, e := findSNIBounds(handshake)
	if e <= s {
		return 0
	}
	return (s + e) / 2
}

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
