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
	firstVIP      uint32 = 0xC6120001
	vipsPerDomain int    = 8
)

var (
	nat64PrefixMu sync.RWMutex
	nat64Prefix   = [12]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}
	nat64Probed   atomic.Bool
)

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
	WiFiPool   []string // All DNS-verified edge IPs resolved on Wi-Fi
	CellPool   []string // All DNS-verified edge IPs resolved on Cellular
	rotIdx     atomic.Uint32
	Updated    time.Time
	readyCh    chan struct{}
	once       sync.Once
	refreshing atomic.Bool
}

// NextAddrs rotates across all DNS-verified edge IPs so consecutive flows
// spread over the CDN's full edge set instead of pinning the first IP.
// Falls back to WiFiAddr/CellAddr when pools are empty.
func (ep *DualEndpoint) NextAddrs() (string, string) {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	idx := int(ep.rotIdx.Add(1))
	w := ep.WiFiAddr
	if len(ep.WiFiPool) > 0 {
		w = ep.WiFiPool[idx%len(ep.WiFiPool)]
	}
	c := ep.CellAddr
	if len(ep.CellPool) > 0 {
		c = ep.CellPool[idx%len(ep.CellPool)]
	}
	return w, c
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

	binder     SocketBinder
	dohClients map[string]*http.Client // Keyed by "link|url" so Cellular never overwrites Wi-Fi!
	dohNext    atomic.Uint64
	resolve    func(ctx context.Context, domain string) (string, string)
}

type dohProvider struct {
	url string
	sni string
}

var dohProvidersWiFi = []dohProvider{
	{url: "https://1.1.1.1/dns-query", sni: "cloudflare-dns.com"},
	{url: "https://9.9.9.9/dns-query", sni: "dns.quad9.net"},
	{url: "https://1.0.0.1/dns-query", sni: "cloudflare-dns.com"},
	{url: "https://8.8.8.8/dns-query", sni: "dns.google"},
}

var dohProvidersCell = []dohProvider{
	{url: "https://[2606:4700:4700::1111]/dns-query", sni: "cloudflare-dns.com"},
	{url: "https://[2620:fe::fe]/dns-query", sni: "dns.quad9.net"},
	{url: "https://1.1.1.1/dns-query", sni: "cloudflare-dns.com"},
	{url: "https://9.9.9.9/dns-query", sni: "dns.quad9.net"},
}

func dohClientKey(link LinkType, url string) string {
	if link == LinkCellular {
		return "cell|" + url
	}
	return "wifi|" + url
}

func NewVIPResolver(binder SocketBinder) *VIPResolver {
	r := &VIPResolver{
		vipToDom:   make(map[uint32]*DualEndpoint),
		domToVIP:   make(map[string]*domainVIPRing),
		binder:     binder,
		dohClients: make(map[string]*http.Client),
	}
	for _, p := range dohProvidersWiFi {
		r.dohClients[dohClientKey(LinkWiFi, p.url)] = newBoundDoHClient(binder, LinkWiFi, p.sni)
	}
	for _, p := range dohProvidersCell {
		r.dohClients[dohClientKey(LinkCellular, p.url)] = newBoundDoHClient(binder, LinkCellular, p.sni)
	}
	r.nextVIP.Store(firstVIP)
	return r
}

func newBoundDoHClient(binder SocketBinder, link LinkType, sni string) *http.Client {
	dialer := NewBoundDialer(binder, link, 1200*time.Millisecond)
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 900 * time.Millisecond,
		TLSClientConfig: &tls.Config{
			ServerName: sni,
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
		pool  []string
	}
	ch := make(chan res, 2)

	// Cross-Radio Oblivious Sharding: Wi-Fi and Cellular resolve concurrently
	// over distinct zero-log DoH authorities; if one radio is offline (e.g. BSNL
	// cellular only), its bind fails fast (<1ms) and applyEndpointAddrs mirrors
	// the working radio's IP.
	go func() {
		ips := r.lookupOnLink(ctx, ep.Domain, LinkWiFi, false)
		r.fireDecoyDoHChaff(LinkWiFi)
		addr := ""
		var pool []string
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				s := v4.String()
				if addr == "" {
					addr = s
				}
				pool = append(pool, s)
			}
		}
		if addr == "" && len(ips) > 0 {
			addr = ips[0].String()
			for _, ip := range ips {
				pool = append(pool, ip.String())
			}
		}
		ch <- res{link: LinkWiFi, addr: addr, pool: pool}
	}()

	go func() {
		ips := r.lookupOnLink(ctx, ep.Domain, LinkCellular, true)
		r.fireDecoyDoHChaff(LinkCellular)
		addr := ""
		rawV4 := ""
		var pool []string
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				if rawV4 == "" {
					rawV4 = v4.String()
				}
			} else if ip.To16() != nil {
				s := ip.String()
				if addr == "" {
					addr = s
				}
				pool = append(pool, s)
			}
		}
		if addr == "" && rawV4 != "" {
			addr = rawV4
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					pool = append(pool, v4.String())
				}
			}
		}
		ch <- res{link: LinkCellular, addr: addr, rawV4: rawV4, pool: pool}
	}()

	var wAddr, cAddr, cRawV4 string
	var wPool, cPool []string
	first := <-ch
	if first.link == LinkWiFi {
		wAddr, wPool = first.addr, first.pool
	} else {
		cAddr, cRawV4, cPool = first.addr, first.rawV4, first.pool
	}

	graceTimer := time.NewTimer(50 * time.Millisecond)
	select {
	case second := <-ch:
		graceTimer.Stop()
		if second.link == LinkWiFi {
			wAddr, wPool = second.addr, second.pool
		} else {
			cAddr, cRawV4, cPool = second.addr, second.rawV4, second.pool
		}
		r.applyEndpointAddrs(ep, wAddr, cAddr, cRawV4, wPool, cPool)
		return
	case <-graceTimer.C:
	}

	if wAddr != "" || cAddr != "" {
		r.applyEndpointAddrs(ep, wAddr, cAddr, cRawV4, wPool, cPool)
		ep.markReady()
	}

	second := <-ch
	if second.link == LinkWiFi {
		wAddr, wPool = second.addr, second.pool
	} else {
		cAddr, cRawV4, cPool = second.addr, second.rawV4, second.pool
	}
	r.applyEndpointAddrs(ep, wAddr, cAddr, cRawV4, wPool, cPool)
}

func (r *VIPResolver) applyEndpointAddrs(ep *DualEndpoint, w, c, cRawV4 string, wPool, cPool []string) {
	ep.mu.Lock()
	if w != "" {
		ep.WiFiAddr = w
	}
	if c != "" {
		ep.CellAddr = c
	}
	if len(wPool) > 0 {
		ep.WiFiPool = wPool
	}
	if len(cPool) > 0 {
		ep.CellPool = cPool
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
	wFinal, cFinal := ep.WiFiAddr, ep.CellAddr
	ep.mu.Unlock()

	// Background-verify Anycast siblings for both radios (never blocks the
	// user path; only verified sockets enter warmPool).
	if wFinal != "" {
		r.maybeWarmAnycastSibling(LinkWiFi, wFinal)
	}
	if cFinal != "" {
		r.maybeWarmAnycastSibling(LinkCellular, cFinal)
	}
}

var decoyDomains = []string{
	"www.wikipedia.org",
	"www.mozilla.org",
	"www.apache.org",
	"www.kernel.org",
	"www.debian.org",
	"www.ietf.org",
}

// fireDecoyDoHChaff sends an asynchronous, zero-latency decoy DoH query over an
// already-open HTTP/2 DoH connection on an alternate authority, blinding ISP
// timing/volume correlation without adding a single millisecond to user traffic.
func (r *VIPResolver) fireDecoyDoHChaff(link LinkType) {
	var rnd [1]byte
	_, _ = rand.Read(rnd[:])
	// Fire on ~50% of lookups so chaff volume itself is non-deterministic.
	if rnd[0]&1 == 0 {
		return
	}
	decoy := decoyDomains[int(rnd[0])%len(decoyDomains)]
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		_ = r.queryDoHOnLink(ctx, decoy, 1, link)
	}()
}

// Shared Anycast front IPs (Cloudflare / Fastly global anycast ingress) that
// hide the specific customer IP range from the ISP while terminating on the
// exact same local Indian PoP hardware.
var sharedCloudflareFronts = []string{
	"104.16.132.229",
	"104.16.133.229",
	"172.64.155.209",
	"162.159.135.42",
}

func isCloudflareAnycast(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 104 && (v4[1] >= 16 && v4[1] <= 31) {
		return true
	}
	if v4[0] == 172 && (v4[1] >= 64 && v4[1] <= 71) {
		return true
	}
	if v4[0] == 162 && (v4[1] == 158 || v4[1] == 159) {
		return true
	}
	return false
}

// maybeWarmAnycastSibling pre-connects a cloaked Anycast front/sibling IP in
// the background and stores it in warmPool under canonicalIP. Because
// ForwardWithMidHandshakeReplay checks isInvalidTLSResponse() and replays the
// buffered ClientHello onto canonicalIP if the server returns a TLS Alert (0x15),
// this hides the destination IP from the ISP with ZERO risk of breaking sites!
func (r *VIPResolver) maybeWarmAnycastSibling(link LinkType, canonicalIP string) {
	parsed := net.ParseIP(canonicalIP)
	if !isCloudflareAnycast(parsed) {
		return
	}
	var rnd [2]byte
	_, _ = rand.Read(rnd[:])
	// Alternate between a shared high-traffic Cloudflare Front IP (completely
	// hiding the target's /24 subnet from the ISP) and a /24 sibling IP.
	var cloakIP string
	if rnd[0]&1 == 0 {
		cloakIP = sharedCloudflareFronts[int(rnd[1])%len(sharedCloudflareFronts)]
	} else {
		v4 := parsed.To4()
		sib := byte(2 + (int(rnd[1]) % 250))
		if sib == v4[3] {
			sib++
		}
		cloakIP = net.IPv4(v4[0], v4[1], v4[2], sib).String()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
		defer cancel()
		d := NewBoundDialer(r.binder, link, 350*time.Millisecond)
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(cloakIP, "443"))
		if err != nil || conn == nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		armKeepAlive(conn)
		PutWarmConn(link, canonicalIP, "443", conn)
	}()
}

func (r *VIPResolver) lookupOnLink(ctx context.Context, domain string, link LinkType, preferV6 bool) []net.IP {
	qtypes := []uint16{1, 28}
	if preferV6 {
		qtypes = []uint16{28, 1}
	}

	type dnsOut struct {
		ips      []net.IP
		priority int
	}
	outCh := make(chan dnsOut, 2)

	for idx, qt := range qtypes {
		go func(qtype uint16, prio int) {
			if ips := r.queryDoHOnLink(ctx, domain, qtype, link); len(ips) > 0 {
				outCh <- dnsOut{ips: ips, priority: prio}
			} else {
				outCh <- dnsOut{ips: nil, priority: prio}
			}
		}(qt, idx+1)
	}

	dohTimer := time.NewTimer(1100 * time.Millisecond)
	defer dohTimer.Stop()

	var fallback []net.IP
	for i := 0; i < 2; i++ {
		select {
		case res := <-outCh:
			if len(res.ips) > 0 {
				if res.priority == 1 {
					return res.ips
				}
				if len(fallback) == 0 {
					fallback = res.ips
				}
			}
		case <-dohTimer.C:
			if len(fallback) > 0 {
				return fallback
			}
			// Cross-link DoH rescue before ever touching UDP/53:
			otherLink := LinkCellular
			if link == LinkCellular {
				otherLink = LinkWiFi
			}
			if ips := r.queryDoHOnLink(ctx, domain, qtypes[0], otherLink); len(ips) > 0 {
				return ips
			}
			return nil
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
	providers := dohProvidersWiFi
	if link == LinkCellular {
		providers = dohProvidersCell
	}
	if len(providers) == 0 {
		return nil
	}
	start := int(r.dohNext.Add(1) % uint64(len(providers)))

	for attempt := 0; attempt < len(providers); attempt++ {
		p := providers[(start+attempt)%len(providers)]
		client := r.dohClients[dohClientKey(link, p.url)]
		if client == nil {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(wireReq))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		status := resp.StatusCode
		resp.Body.Close()
		if err != nil || status != http.StatusOK {
			continue
		}
		if ips := parseDNSResponsePacket(body, txID); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func (r *VIPResolver) queryUDPOnLink(ctx context.Context, domain string, qtype uint16, link LinkType) []net.IP {
	// Zero-plaintext policy: legacy callers (e.g. the RRC keep-awake pacer)
	// are routed through encrypted DoH so UDP/53 is never leaked.
	if ips := r.queryDoHOnLink(ctx, domain, qtype, link); len(ips) > 0 {
		return ips
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
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	if padEDNS {
		binary.BigEndian.PutUint16(hdr[10:12], 1)
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
	binary.BigEndian.PutUint16(qtail[2:4], 1)
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
			// Fill EDNS0 padding with cryptographic pseudorandom bytes instead
			// of 0x00 so TLS compression/entropy side-channels learn nothing.
			noise := make([]byte, padLen)
			GlobalPrivacy.FillCryptoRandom(noise)
			buf.Write(noise)
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
