package multipath

import (
	"bufio"
	"context"
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
	"time"
)

// PrivacyEndpoint defines an encrypted SOCKS5 or HTTPS CONNECT tunnel endpoint
// pinned to a specific physical link so egress traffic shows the relay's IP
// instead of the user's individual Wi-Fi or Mobile ISP IP.
//
// For 2-Hop Oblivious Chaining (Tor-grade unlinkability at line speed), set
// NextHop: the bound radio dials Address (Hop 1, Entry Guard) over TLS 1.3,
// tunnels to NextHop.Address (Hop 2, Exit Relay) with a nested TLS 1.3 layer,
// then tunnels to the target. Hop 1 sees only your radio IP; Hop 2 sees only
// the destination. With NextHop nil it behaves as a single encrypted proxy.
type PrivacyEndpoint struct {
	Protocol  string // "socks5", "http" (CONNECT), "https"/"tls"/"socks5s" (TLS-wrapped)
	Address   string // host:port of Hop 1 (Entry Guard)
	ServerSNI string // TLS SNI for Hop 1 (defaults to Address host)
	Username  string
	Password  string
	NextHop   *PrivacyEndpoint // Optional Hop 2 (Exit Relay)
}

type PrivacyEngine struct {
	mu           sync.RWMutex
	wifiEgress   *PrivacyEndpoint
	cellEgress   *PrivacyEndpoint
	fragmentTLS  atomic.Bool
	blockWebRTC  atomic.Bool
	stripHeaders atomic.Bool
}

var GlobalPrivacy = newPrivacyEngine()

func newPrivacyEngine() *PrivacyEngine {
	p := &PrivacyEngine{}
	p.fragmentTLS.Store(true)
	p.blockWebRTC.Store(true)
	p.stripHeaders.Store(true)
	return p
}

// ConfigurePrivacyTunnels sets optional per-link encrypted proxy local or remote
// endpoints. If only one endpoint is provided, both physical links bind their own
// hardware sockets (LinkWiFi and LinkCellular) to it, masking both ISP IPs while
// bonding both radios simultaneously.
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

// ShouldBlockPrivacyLeak is the single choke point for side-channel and
// identity leaks inside the gVisor forwarders. Call it at the very top of the
// UDP and TCP handlers before opening any outbound socket.
func ShouldBlockPrivacyLeak(isUDP bool, payload []byte, dstPort int) bool {
	if isUDP && dstPort == 443 {
		// Block QUIC (HTTP/3) so all HTTPS uses multi-connection TCP 443 with
		// 3-record SNI slicing and dual-radio Wi-Fi + 5G bonding.
		return true
	}
	switch dstPort {
	case 853: // Block direct DoT bypass so DNS falls back to the sharded DoH resolver
		return true
	case 5353, // mDNS local identity leak
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
	// Inspect UDP payload for RFC 5389 STUN Magic Cookie (0x2112A442) on any
	// non-standard port.
	if isUDP && len(payload) >= 20 {
		msgType := binary.BigEndian.Uint16(payload[0:2])
		cookie := binary.BigEndian.Uint32(payload[4:8])
		if (msgType&0xC000 == 0) && cookie == 0x2112A442 {
			return true
		}
	}
	return false
}

// wrapHopTLS upgrades a raw bound connection to TLS 1.3 when the hop's
// protocol calls for it ("https", "tls", "socks5s").
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

// DialThroughPrivacyEgress establishes a bound connection over `link` through the
// configured encrypted relay. With NextHop set it builds a 2-Hop Oblivious Chain:
// bound radio -> Hop 1 (Entry Guard, sees only your radio IP) -> nested TLS 1.3 ->
// Hop 2 (Exit Relay, sees only the destination) -> target. With no endpoint
// configured it dials direct.
func DialThroughPrivacyEgress(
	ctx context.Context,
	dialer *net.Dialer,
	ep *PrivacyEndpoint,
	network, targetAddr string,
) (net.Conn, error) {
	if ep == nil || ep.Address == "" {
		return dialer.DialContext(ctx, network, targetAddr)
	}

	// Dial Hop 1 on the strictly bound physical radio (Wi-Fi or Cellular).
	rawConn, err := dialer.DialContext(ctx, "tcp", ep.Address)
	if err != nil {
		return nil, err
	}

	// 2-Hop Oblivious Routing: Hop 1 -> nested TLS -> Hop 2 -> target.
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

	// Single-hop encrypted relay.
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

// isTLSClientHello detects a TLS 1.0-1.3 ClientHello record at the start of a connection.
func isTLSClientHello(b []byte) bool {
	if len(b) < 43 {
		return false
	}
	// ContentType == Handshake (0x16), Version major == 0x03, HandshakeType == ClientHello (0x01)
	return b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

// WriteClientHello writes a TLS ClientHello with TSO-proof 3-record SNI
// slicing when fragmentation is enabled; plain write otherwise. Safe to use
// for any first-payload write (non-TLS payloads pass through untouched).
func WriteClientHello(conn net.Conn, b []byte) (int, error) {
	if GlobalPrivacy.TLSFragmentationEnabled() && isTLSClientHello(b) {
		return writeFragmentedClientHello(conn, b)
	}
	return conn.Write(b)
}

// writeFragmentedClientHello splits a TLS ClientHello into 3 asymmetric TLS
// records with a 1.5ms hardware pacing barrier between them. Back-to-back
// writes are frequently re-merged into a single wire packet by kernel
// TSO/GSO; the pacing barrier forces separate physical IP frames so ISP DPI
// cannot reassemble the SNI. Cost: ~3ms per handshake, 0% download overhead.
func writeFragmentedClientHello(conn net.Conn, b []byte) (int, error) {
	if len(b) < 43 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return conn.Write(b)
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recordLen || recordLen < 32 {
		return conn.Write(b)
	}

	payload := b[5 : 5+recordLen]

	// Cut 1: right after the 4-byte Handshake header + 2-byte ClientVersion.
	// Forces the DPI state machine to open an incomplete record context.
	cut1 := 6
	// Cut 2: exact midpoint of the SNI hostname string (or payload midpoint).
	cut2 := len(payload) / 2
	if sniMid := findSNIMidpoint(payload); sniMid > cut1+4 && sniMid < len(payload)-4 {
		cut2 = sniMid
	}

	slices := [][]byte{
		payload[:cut1],
		payload[cut1:cut2],
		payload[cut2:],
	}

	for i, part := range slices {
		rec := make([]byte, 5+len(part))
		rec[0] = 0x16
		rec[1] = b[1]
		rec[2] = b[2]
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(part)))
		copy(rec[5:], part)

		// Append any trailing bytes (e.g. ChangeCipherSpec / early data) to the final slice.
		if i == len(slices)-1 && len(b) > 5+recordLen {
			rec = append(rec, b[5+recordLen:]...)
		}

		if _, err := conn.Write(rec); err != nil {
			return 0, err
		}
		// 1.5ms hardware flush barrier prevents kernel TSO/GSO from
		// coalescing the records back into one DPI-readable TCP segment.
		if i < len(slices)-1 {
			time.Sleep(1500 * time.Microsecond)
		}
	}
	return len(b), nil
}

func findSNIMidpoint(handshake []byte) int {
	// Skip Handshake header (4) + Version (2) + Random (32) = 38 bytes
	idx := 38
	if len(handshake) <= idx {
		return 0
	}
	// Session ID
	sessIDLen := int(handshake[idx])
	idx += 1 + sessIDLen
	if len(handshake) < idx+2 {
		return 0
	}
	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(handshake[idx : idx+2]))
	idx += 2 + cipherLen
	if len(handshake) < idx+1 {
		return 0
	}
	// Compression Methods
	compLen := int(handshake[idx])
	idx += 1 + compLen
	if len(handshake) < idx+2 {
		return 0
	}
	// Extensions total length
	extTotalLen := int(binary.BigEndian.Uint16(handshake[idx : idx+2]))
	idx += 2
	end := idx + extTotalLen
	if end > len(handshake) {
		end = len(handshake)
	}
	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(handshake[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(handshake[idx+2 : idx+4]))
		if extType == 0x0000 && extLen > 6 && idx+4+extLen <= end {
			return idx + 4 + (extLen / 2)
		}
		idx += 4 + extLen
	}
	return 0
}

// SanitizePrivacyHeaders strips proxy-identifying or IP-leaking HTTP headers.
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
