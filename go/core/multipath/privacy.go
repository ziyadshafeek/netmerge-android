package multipath

import (
	"bufio"
	"context"
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
// pinned to a specific physical link so egress traffic shows the relay's Anycast
// IP instead of the user's individual Wi-Fi or Mobile ISP IP.
type PrivacyEndpoint struct {
	Protocol string // "socks5" or "http" (HTTP CONNECT)
	Address  string // host:port
	Username string
	Password string
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

// IsSTUNOrDiscoveryLeak inspects a UDP payload or target port to detect WebRTC
// STUN/TURN binding requests (RFC 5389 magic cookie 0x2112A442) that leak real
// client Wi-Fi and Cellular IP addresses to websites.
func IsSTUNOrDiscoveryLeak(payload []byte, dstPort int) bool {
	if !GlobalPrivacy.WebRTCBlockingEnabled() {
		return false
	}
	if dstPort == 3478 || dstPort == 5349 || dstPort == 19302 || dstPort == 19305 {
		return true
	}
	// RFC 5389 STUN header is 20 bytes; bytes 4..8 equal magic cookie 0x2112A442.
	if len(payload) >= 20 {
		msgType := binary.BigEndian.Uint16(payload[0:2])
		cookie := binary.BigEndian.Uint32(payload[4:8])
		if (msgType&0xC000 == 0) && cookie == 0x2112A442 {
			return true
		}
	}
	return false
}

// DialThroughPrivacyEgress establishes a bound connection over `link` through the
// configured encrypted SOCKS5 or HTTP CONNECT privacy relay so the destination only
// sees the relay's shared IP instead of the individual ISP IP. With no endpoint
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

	rawConn, err := dialer.DialContext(ctx, "tcp", ep.Address)
	if err != nil {
		return nil, err
	}

	proto := strings.ToLower(strings.TrimSpace(ep.Protocol))
	if proto == "http" || proto == "https" || proto == "connect" {
		if err := handshakeHTTPConnect(ctx, rawConn, targetAddr, ep.Username, ep.Password); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		return rawConn, nil
	}

	if err := handshakeSOCKS5(ctx, rawConn, targetAddr, ep.Username, ep.Password); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return rawConn, nil
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

// writeFragmentedClientHello splits a TLS ClientHello into 2 TLS records right across
// the middle of the SNI extension (or handshake body) and writes them in separate
// TCP segments so ISP DPI middleboxes cannot parse or log the destination domain.
func writeFragmentedClientHello(conn net.Conn, b []byte) (int, error) {
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recordLen || recordLen < 32 {
		return conn.Write(b)
	}

	payload := b[5 : 5+recordLen]
	splitPos := len(payload) / 2
	// Locate the SNI extension midpoint if present for exact DPI desynchronization.
	if sniMid := findSNIMidpoint(payload); sniMid > 8 && sniMid < len(payload)-4 {
		splitPos = sniMid
	}

	part1 := payload[:splitPos]
	part2 := payload[splitPos:]

	rec1 := make([]byte, 5+len(part1))
	rec1[0] = 0x16
	rec1[1] = b[1]
	rec1[2] = b[2]
	binary.BigEndian.PutUint16(rec1[3:5], uint16(len(part1)))
	copy(rec1[5:], part1)

	rec2 := make([]byte, 5+len(part2)+len(b)-(5+recordLen))
	rec2[0] = 0x16
	rec2[1] = b[1]
	rec2[2] = b[2]
	binary.BigEndian.PutUint16(rec2[3:5], uint16(len(part2)))
	copy(rec2[5:], part2)
	if len(b) > 5+recordLen {
		copy(rec2[5+len(part2):], b[5+recordLen:])
	}

	if _, err := conn.Write(rec1); err != nil {
		return 0, err
	}
	if _, err := conn.Write(rec2); err != nil {
		return len(part1), err
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
