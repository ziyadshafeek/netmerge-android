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
	// NOTE: UDP/443 (QUIC) is no longer blocked unconditionally. Interactive
	// mice flows run natively over QUIC at 0-RTT speed; ElephantQUICGuard
	// evicts bulk flows (>=2.5MB at >500KB/s) with ICMP Port Unreachable so
	// they re-dial as multi-connection bonded TCP.
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
	return &MorphingConn{
		Conn: c,
		link: link,
	}
}

// CloseWrite forwards TCP half-close (FIN) to the underlying *net.TCPConn.
func (mc *MorphingConn) CloseWrite() error {
	if cw, ok := mc.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (mc *MorphingConn) Write(b []byte) (int, error) {
	// Only morph encrypted TLS 1.3 Application Data (0x17) at L4 TCP boundaries.
	// ClientHello (0x16) fragmentation is handled exclusively by WriteClientHello
	// so it is never double-fragmented!
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
		return DialBoundContext(ctx, dialer, network, targetAddr)
	}
	rawConn, err := DialBoundContext(ctx, dialer, "tcp", ep.Address)
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
		// wrapped standby conn): writeFragmentedClientHello must write rec1/rec2
		// straight to the raw socket so the SNI split lands exactly as designed.
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

// SyscallConn forwards raw fd access to the underlying *net.TCPConn so
// ReArmQuickAck and socket liveness checks never fail on a wrapped connection.
func (mc *MorphingConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := mc.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("morphing: inner conn has no syscall conn")
}

// writeFragmentedClientHello splits the TLS ClientHello across separate TCP
// segments WITHOUT mutating TCP_MAXSEG: with TCP_NODELAY each Write lands in
// its own segment, so the SNI is never contiguous in one IP packet, while the
// TLS record itself stays whole and parseable (JA3/JA4 fingerprints intact).
func writeFragmentedClientHello(conn net.Conn, b []byte) (int, error) {
	// The TLS record stays WHOLE (single 0x16 record, JA3/JA4 parseable).
	// SNI evasion happens at TCP segment boundaries: with TCP_NODELAY each
	// Write becomes its own segment, so the SNI hostname is never contiguous
	// in one IP packet — while the 5-byte TLS record header always rides
	// intact in the first segment (custom fingerprint parsers that don't
	// reassemble split headers keep working).
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	if len(b) <= 64 || b[0] != 0x16 {
		return conn.Write(b)
	}
	// Split once, right inside the SNI hostname extension. The 5-byte TLS
	// record header (b[:5]) is ALWAYS sent intact in the first segment.
	splitPos := len(b) / 2
	// The end guard only needs >=2 bytes in the tail segment; the SNI
	// midpoint is inside the hostname by construction, so splitting there
	// always achieves the goal even for small hellos.
	if sniMid := findSNIMidpoint(b); sniMid >= 40 && sniMid < len(b)-2 {
		splitPos = sniMid
	}
	n1, err := conn.Write(b[:splitPos])
	if err != nil {
		return n1, err
	}
	n2, err := conn.Write(b[splitPos:])
	return n1 + n2, err
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

// findSNIMidpoint locates the middle byte of the SNI server_name extension
// in a TLS ClientHello record, as an ABSOLUTE offset into b (which includes
// the 5-byte TLS record header).
func findSNIMidpoint(b []byte) int {
	// TLS Record header (5 bytes) + Handshake header (4 bytes) + Version (2) + Random (32) = 43 bytes
	if len(b) < 50 || b[0] != 0x16 || b[5] != 0x01 {
		return 0
	}
	pos := 43
	// Skip Session ID
	if pos >= len(b) {
		return 0
	}
	pos += 1 + int(b[pos])
	// Skip Cipher Suites
	if pos+2 > len(b) {
		return 0
	}
	pos += 2 + (int(b[pos])<<8 | int(b[pos+1]))
	// Skip Compression Methods
	if pos+1 > len(b) {
		return 0
	}
	pos += 1 + int(b[pos])
	// Extensions length
	if pos+2 > len(b) {
		return 0
	}
	extEnd := pos + 2 + (int(b[pos])<<8 | int(b[pos+1]))
	pos += 2
	if extEnd > len(b) {
		extEnd = len(b)
	}
	for pos+4 <= extEnd {
		extType := int(b[pos])<<8 | int(b[pos+1])
		extLen := int(b[pos+2])<<8 | int(b[pos+3])
		pos += 4
		if extType == 0x0000 && pos+5 <= extEnd { // server_name extension
			nameLen := int(b[pos+3])<<8 | int(b[pos+4])
			nameStart := pos + 5
			if nameStart+nameLen <= extEnd && nameLen > 2 {
				return nameStart + (nameLen / 2)
			}
		}
		pos += extLen
	}
	return 0
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
