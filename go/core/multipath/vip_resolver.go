package multipath

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 198.18.0.1 (RFC 2544 benchmark range) allocated as a ring of 8 VIPs per domain.
	firstVIP      uint32 = 0xC6120001
	vipsPerDomain int    = 8
)

var (
	// Discovered 96-bit carrier NAT64 prefix (defaults to RFC 6052 well-known 64:ff9b::/96).
	nat64PrefixMu sync.RWMutex
	nat64Prefix   = [12]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}
	nat64Probed   atomic.Bool
)

// SynthesizeCarrierNAT64 converts an IPv4 address into a carrier NAT64 IPv6 address.
func SynthesizeCarrierNAT64(ip4 net.IP) string {
	v4 := ip4.To4()
	if v4 == nil {
		return ""
	}
	nat64PrefixMu.RLock()
	pfx := nat64Prefix
	nat64PrefixMu.RUnlock()

	out := make(net.IP, 16)
	copy(out[0:12], pfx[:])
	out[12] = v4[0]
	out[13] = v4[1]
	out[14] = v4[2]
	out[15] = v4[3]
	return out.String()
}

type DualEndpoint struct {
	Domain     string
	mu         sync.RWMutex
	WiFiAddr   string
	CellAddr   string
	CellRawV4  string
	Updated    time.Time
	readyCh    chan struct{}
	once       sync.Once
	refreshing atomic.Bool
}

func (ep *DualEndpoint) markReady() {
	ep.once.Do(func() {
		if ep.readyCh != nil {
			close(ep.readyCh)
		}
	})
}

func (ep *DualEndpoint) WaitReady(ctx context.Context) (string, string) {
	if ep.readyCh != nil {
		select {
		case <-ep.readyCh:
		case <-ctx.Done():
		case <-time.After(1500 * time.Millisecond):
		}
	}
	ep.mu.RLock()
	w, c := ep.WiFiAddr, ep.CellAddr
	ep.mu.RUnlock()
	return w, c
}

func (ep *DualEndpoint) Addrs() (string, string) {
	ep.mu.RLock()
	w, c := ep.WiFiAddr, ep.CellAddr
	ep.mu.RUnlock()
	return w, c
}

type domainVIPRing struct {
	vips [vipsPerDomain]uint32
	idx  atomic.Uint32
	ep   *DualEndpoint
}

type VIPResolver struct {
	mu       sync.RWMutex
	vipToDom map[uint32]*DualEndpoint
	domToVIP map[string]*domainVIPRing
	nextVIP  atomic.Uint32

	binder        SocketBinder
	dohClientWiFi *http.Client
	dohClientCell *http.Client
	resolve       func(ctx context.Context, domain string) (string, string)
}

func NewVIPResolver(binder SocketBinder) *VIPResolver {
	r := &VIPResolver{
		vipToDom:      make(map[uint32]*DualEndpoint),
		domToVIP:      make(map[string]*domainVIPRing),
		binder:        binder,
		dohClientWiFi: newBoundDoHClient(binder, LinkWiFi),
		dohClientCell: newBoundDoHClient(binder, LinkCellular),
	}
	r.nextVIP.Store(firstVIP)
	return r
}

// newBoundDoHClient creates a persistent HTTP/2 TLS 1.3 client strictly bound
// to a single physical radio so DNS queries never leak file descriptors.
func newBoundDoHClient(binder SocketBinder, link LinkType) *http.Client {
	dialer := NewBoundDialer(binder, link, 1200*time.Millisecond)
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 900 * time.Millisecond,
		TLSClientConfig: &tls.Config{
			ServerName: "cloudflare-dns.com",
			MinVersion: tls.VersionTLS13,
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   1100 * time.Millisecond,
	}
}

func (r *VIPResolver) maybeDiscoverNAT64Prefix() {
	if !nat64Probed.CompareAndSwap(false, true) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()
		ips := r.lookupOnLink(ctx, "ipv4only.arpa", LinkCellular, true)
		for _, ip := range ips {
			if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
				nat64PrefixMu.Lock()
				copy(nat64Prefix[:], v6[0:12])
				nat64PrefixMu.Unlock()
				return
			}
		}
	}()
}

func (r *VIPResolver) GetOrAllocate(ctx context.Context, domain string) (net.IP, *DualEndpoint) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, nil
	}
	r.maybeDiscoverNAT64Prefix()

	r.mu.RLock()
	if ring, ok := r.domToVIP[domain]; ok {
		r.mu.RUnlock()
		pick := ring.vips[ring.idx.Add(1)%uint32(vipsPerDomain)]
		w, c := ring.ep.Addrs()
		if (w == "" || c == "") || time.Since(ring.ep.Updated) > 60*time.Second {
			if ring.ep.refreshing.CompareAndSwap(false, true) {
				go func(ep *DualEndpoint) {
					defer ep.refreshing.Store(false)
					r.populateEndpoint(ep)
				}(ring.ep)
			}
		}
		return vipFromInt(pick), ring.ep
	}
	r.mu.RUnlock()

	if r.resolve != nil {
		w, c := r.resolve(ctx, domain)
		if w == "" && c == "" {
			return nil, nil
		}
		if w == "" {
			w = c
		}
		if c == "" {
			c = w
		}
		r.mu.Lock()
		if ring, ok := r.domToVIP[domain]; ok {
			r.mu.Unlock()
			pick := ring.vips[ring.idx.Add(1)%uint32(vipsPerDomain)]
			return vipFromInt(pick), ring.ep
		}
		ep := &DualEndpoint{
			Domain:   domain,
			WiFiAddr: w,
			CellAddr: c,
			Updated:  time.Now(),
			readyCh:  make(chan struct{}),
		}
		ep.markReady()
		ring := r.allocateRingLocked(domain, ep)
		r.mu.Unlock()
		return vipFromInt(ring.vips[0]), ep
	}

	r.mu.Lock()
	if ring, ok := r.domToVIP[domain]; ok {
		r.mu.Unlock()
		pick := ring.vips[ring.idx.Add(1)%uint32(vipsPerDomain)]
		return vipFromInt(pick), ring.ep
	}
	ep := &DualEndpoint{
		Domain:  domain,
		readyCh: make(chan struct{}),
	}
	ep.refreshing.Store(true)
	ring := r.allocateRingLocked(domain, ep)
	r.mu.Unlock()

	go func() {
		defer ep.refreshing.Store(false)
		r.populateEndpoint(ep)
	}()
	return vipFromInt(ring.vips[0]), ep
}

func (r *VIPResolver) allocateRingLocked(domain string, ep *DualEndpoint) *domainVIPRing {
	ring := &domainVIPRing{ep: ep}
	for i := 0; i < vipsPerDomain; i++ {
		v := r.nextVIP.Add(1) - 1
		ring.vips[i] = v
		r.vipToDom[v] = ep
	}
	r.domToVIP[domain] = ring
	return ring
}

func (r *VIPResolver) LookupVIP(ip net.IP) (*DualEndpoint, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, false
	}
	key := binary.BigEndian.Uint32(v4)
	r.mu.RLock()
	ep, ok := r.vipToDom[key]
	r.mu.RUnlock()
	return ep, ok
}

func (r *VIPResolver) populateEndpoint(ep *DualEndpoint) {
	defer ep.markReady()

	ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
	defer cancel()

	type res struct {
		link  LinkType
		addr  string
		rawV4 string
	}
	ch := make(chan res, 2)

	// Wi-Fi resolution: prefers IPv4 (A) then IPv6 (AAAA).
	go func() {
		ips := r.lookupOnLink(ctx, ep.Domain, LinkWiFi, false)
		addr := ""
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				addr = v4.String()
				break
			}
		}
		if addr == "" && len(ips) > 0 {
			addr = ips[0].String()
		}
		ch <- res{link: LinkWiFi, addr: addr}
	}()

	// Cellular resolution: prefers native IPv6 (AAAA) first; retains raw IPv4 fallback
	// so dual-stack or CLAT 5G bearers can try both native IPv6/NAT64 and IPv4 seamlessly.
	go func() {
		ips := r.lookupOnLink(ctx, ep.Domain, LinkCellular, true)
		addr := ""
		rawV4 := ""
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil && rawV4 == "" {
				rawV4 = v4.String()
			}
			if ip.To4() == nil && ip.To16() != nil && addr == "" {
				addr = ip.String()
			}
		}
		if addr == "" && rawV4 != "" {
			addr = rawV4
		}
		ch <- res{link: LinkCellular, addr: addr, rawV4: rawV4}
	}()

	var wAddr, cAddr, cRawV4 string
	first := <-ch
	if first.link == LinkWiFi {
		wAddr = first.addr
	} else {
		cAddr = first.addr
		cRawV4 = first.rawV4
	}

	graceTimer := time.NewTimer(75 * time.Millisecond)
	select {
	case second := <-ch:
		graceTimer.Stop()
		if second.link == LinkWiFi {
			wAddr = second.addr
		} else {
			cAddr = second.addr
			cRawV4 = second.rawV4
		}
		r.applyEndpointAddrs(ep, wAddr, cAddr, cRawV4)
		return
	case <-graceTimer.C:
	}

	if wAddr != "" || cAddr != "" {
		r.applyEndpointAddrs(ep, wAddr, cAddr, cRawV4)
		ep.markReady()
	}

	second := <-ch
	if second.link == LinkWiFi {
		wAddr = second.addr
	} else {
		cAddr = second.addr
		cRawV4 = second.rawV4
	}
	r.applyEndpointAddrs(ep, wAddr, cAddr, cRawV4)
}

func (r *VIPResolver) applyEndpointAddrs(ep *DualEndpoint, w, c, cRawV4 string) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if w != "" {
		ep.WiFiAddr = w
	}
	if c != "" {
		ep.CellAddr = c
	}
	if cRawV4 != "" {
		ep.CellRawV4 = cRawV4
	} else if parsed := net.ParseIP(ep.WiFiAddr); parsed != nil && parsed.To4() != nil {
		ep.CellRawV4 = ep.WiFiAddr
	}
	if ep.WiFiAddr == "" && ep.CellAddr != "" {
		if ep.CellRawV4 != "" {
			ep.WiFiAddr = ep.CellRawV4
		} else {
			ep.WiFiAddr = ep.CellAddr
		}
	}
	if ep.CellAddr == "" && ep.WiFiAddr != "" {
		ep.CellAddr = ep.WiFiAddr
	}
	if ep.WiFiAddr != "" || ep.CellAddr != "" {
		ep.Updated = time.Now()
	}
}

func (r *VIPResolver) lookupOnLink(ctx context.Context, domain string, link LinkType, preferV6 bool) []net.IP {
	qtypes := []uint16{1, 28} // A, AAAA
	if preferV6 {
		qtypes = []uint16{28, 1} // AAAA first on 5G
	}

	type dnsOut struct {
		ips      []net.IP
		priority int
	}
	outCh := make(chan dnsOut, 4)

	// 1. Encrypted DoH over persistent bound HTTP/2 client (zero FD leak).
	go func() {
		ips := r.queryDoHOnLink(ctx, domain, qtypes[0], link)
		if len(ips) > 0 {
			outCh <- dnsOut{ips: ips, priority: 1}
		}
	}()

	// 2. Parallel UDP race across primary & secondary DNS resolvers on bound link.
	for idx, qt := range qtypes {
		go func(qtype uint16, prio int) {
			ips := r.queryUDPOnLink(ctx, domain, qtype, link)
			if len(ips) > 0 {
				outCh <- dnsOut{ips: ips, priority: prio}
			}
		}(qt, idx+1)
	}

	timeout := time.NewTimer(900 * time.Millisecond)
	defer timeout.Stop()

	var fallback []net.IP
	for i := 0; i < 3; i++ {
		select {
		case res := <-outCh:
			if res.priority == 1 {
				return res.ips
			}
			if len(fallback) == 0 {
				fallback = res.ips
			}
		case <-timeout.C:
			return fallback
		case <-ctx.Done():
			return fallback
		}
	}
	return fallback
}

func (r *VIPResolver) queryDoHOnLink(ctx context.Context, domain string, qtype uint16, link LinkType) []net.IP {
	wireReq, txID := buildDNSQueryPacket(domain, qtype, true)
	if len(wireReq) == 0 {
		return nil
	}
	dohURL := "https://1.1.1.1/dns-query"
	client := r.dohClientWiFi
	if link == LinkCellular {
		dohURL = "https://[2606:4700:4700::1111]/dns-query"
		client = r.dohClientCell
	}
	if client == nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(wireReq))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil && link == LinkCellular {
		// Fallback to IPv4 DoH endpoint on Cellular if carrier uses CLAT/IPv4.
		reqV4, errReq := http.NewRequestWithContext(ctx, http.MethodPost, "https://1.1.1.1/dns-query", bytes.NewReader(wireReq))
		if errReq == nil {
			reqV4.Header.Set("Content-Type", "application/dns-message")
			reqV4.Header.Set("Accept", "application/dns-message")
			resp, err = client.Do(reqV4)
		}
	}
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}
	return parseDNSResponsePacket(body, txID)
}

func (r *VIPResolver) queryUDPOnLink(ctx context.Context, domain string, qtype uint16, link LinkType) []net.IP {
	wireReq, txID := buildDNSQueryPacket(domain, qtype, false)
	if len(wireReq) == 0 {
		return nil
	}
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if link == LinkCellular {
		servers = []string{"[2606:4700:4700::1111]:53", "1.1.1.1:53", "[2001:4860:4860::8888]:53"}
	}

	dialer := NewBoundDialer(r.binder, link, 550*time.Millisecond)
	for _, srv := range servers {
		conn, err := dialer.DialContext(ctx, "udp", srv)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(450 * time.Millisecond))
		_, err = conn.Write(wireReq)
		if err != nil {
			_ = conn.Close()
			continue
		}
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil || n < 12 {
			continue
		}
		if ips := parseDNSResponsePacket(buf[:n], txID); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func buildDNSQueryPacket(domain string, qtype uint16, padEDNS bool) ([]byte, uint16) {
	var randBytes [2]byte
	_, _ = rand.Read(randBytes[:])
	txID := binary.BigEndian.Uint16(randBytes[:])

	var buf bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // Standard query, RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	if padEDNS {
		binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT=1 (EDNS0 OPT)
	}
	buf.Write(hdr[:])

	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)

	var qtail [4]byte
	binary.BigEndian.PutUint16(qtail[0:2], qtype)
	binary.BigEndian.PutUint16(qtail[2:4], 1) // QCLASS=IN
	buf.Write(qtail[:])

	if padEDNS {
		curLen := buf.Len() + 15
		padLen := (128 - (curLen % 128)) % 128
		buf.WriteByte(0)
		var optHdr [10]byte
		binary.BigEndian.PutUint16(optHdr[0:2], 41)
		binary.BigEndian.PutUint16(optHdr[2:4], 1232)
		binary.BigEndian.PutUint16(optHdr[8:10], uint16(4+padLen))
		buf.Write(optHdr[:])

		var padOpt [4]byte
		binary.BigEndian.PutUint16(padOpt[0:2], 12)
		binary.BigEndian.PutUint16(padOpt[2:4], uint16(padLen))
		buf.Write(padOpt[:])
		if padLen > 0 {
			buf.Write(make([]byte, padLen))
		}
	}

	return buf.Bytes(), txID
}

func parseDNSResponsePacket(pkt []byte, expectedTxID uint16) []net.IP {
	if len(pkt) < 12 {
		return nil
	}
	if expectedTxID != 0 && binary.BigEndian.Uint16(pkt[0:2]) != expectedTxID {
		return nil
	}
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	offset := 12

	for i := 0; i < qdCount; i++ {
		next, ok := skipDNSName(pkt, offset)
		if !ok || next+4 > len(pkt) {
			return nil
		}
		offset = next + 4
	}

	var ips []net.IP
	for i := 0; i < anCount; i++ {
		next, ok := skipDNSName(pkt, offset)
		if !ok || next+10 > len(pkt) {
			break
		}
		offset = next
		rtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(pkt[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(pkt) {
			break
		}
		if rtype == 1 && rdLen == 4 {
			ip := make(net.IP, 4)
			copy(ip, pkt[offset:offset+4])
			ips = append(ips, ip)
		} else if rtype == 28 && rdLen == 16 {
			ip := make(net.IP, 16)
			copy(ip, pkt[offset:offset+16])
			ips = append(ips, ip)
		}
		offset += rdLen
	}
	return ips
}

func skipDNSName(pkt []byte, offset int) (int, bool) {
	for {
		if offset >= len(pkt) {
			return 0, false
		}
		b := pkt[offset]
		if b == 0 {
			return offset + 1, true
		}
		if b&0xC0 == 0xC0 {
			if offset+2 > len(pkt) {
				return 0, false
			}
			return offset + 2, true
		}
		offset += int(b) + 1
	}
}

func vipFromInt(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
