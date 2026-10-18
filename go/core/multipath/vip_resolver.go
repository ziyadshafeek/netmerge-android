package multipath

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	nat64PrefixMu     sync.RWMutex
	nat64Prefix       = [12]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}
	nat64Probed       atomic.Bool
	nat64Verified     atomic.Bool
	activeVIPResolver atomic.Pointer[VIPResolver]
)

func IsNAT64PrefixVerified() bool {
	return nat64Verified.Load()
}

// NotifyNetworkHandover is called whenever Android reports a network/RAT change
// (e.g. Jio 5G -> 4G). It purges dead 5G pre-warmed sockets, closes zombie HTTP/2
// DoH connections, clears link stall timers, and marks cached endpoints for refresh.
func NotifyNetworkHandover() {
	PurgeWarmPool()
	stalledUntil[LinkWiFi].Store(0)
	stalledUntil[LinkCellular].Store(0)
	nat64Verified.Store(false)
	nat64Probed.Store(false)
	if r := activeVIPResolver.Load(); r != nil {
		for _, client := range r.dohClients {
			if client != nil {
				client.CloseIdleConnections()
			}
		}
		r.mu.RLock()
		for _, ring := range r.domToVIP {
			if ring != nil && ring.ep != nil {
				ring.ep.mu.Lock()
				ring.ep.Updated = time.Time{} // Force background refresh on next query
				ring.ep.mu.Unlock()
			}
		}
		r.mu.RUnlock()
	}
}

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
	mu         sync.RWMutex
	vipToDom   map[uint32]*DualEndpoint
	domToVIP   map[string]*domainVIPRing
	nextVIP    atomic.Uint32
	binder     SocketBinder
	dohClients map[string]*http.Client
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
	{url: "https://1.1.1.1/dns-query", sni: "cloudflare-dns.com"},
	{url: "https://[2606:4700:4700::1111]/dns-query", sni: "cloudflare-dns.com"},
	{url: "https://9.9.9.9/dns-query", sni: "dns.quad9.net"},
	{url: "https://[2620:fe::fe]/dns-query", sni: "dns.quad9.net"},
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
	activeVIPResolver.Store(r)
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
		// Verify whether 64:ff9b::101:101:443 is actually routable on this carrier
		// before enabling NAT64 dual-exit striping.
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		d := NewBoundDialer(r.binder, LinkCellular, 1000*time.Millisecond)
		c, err := d.DialContext(ctx, "tcp6", "[64:ff9b::101:101]:443")
		if err == nil && c != nil {
			_ = c.Close()
			nat64Verified.Store(true)
		} else {
			nat64Verified.Store(false)
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
	wFinal, cFinal, dom := ep.WiFiAddr, ep.CellAddr, ep.Domain
	ep.mu.Unlock()
	if wFinal != "" {
		r.verifyAndWarmAnycastCloak(LinkWiFi, dom, wFinal)
	}
	if cFinal != "" {
		r.verifyAndWarmAnycastCloak(LinkCellular, dom, cFinal)
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

func (r *VIPResolver) fireDecoyDoHChaff(link LinkType) {
	var rnd [1]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])
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

// verifyAndWarmAnycastCloak solves the v4 TLS Alert & ClientHello.random replay
// leak: it first verifies a candidate Anycast cloak IP in the background using
// a disposable RFC 8446 probe ClientHello with a fresh CSPRNG nonce. ONLY if
// the cloak IP responds with a valid ServerHello (0x16) for `domain` does it
// open a clean, 0-byte pre-warmed socket and store it in warmPool!
func (r *VIPResolver) verifyAndWarmAnycastCloak(link LinkType, domain, canonicalIP string) {
	if !GlobalPrivacy.AnycastCloakEnabled() || domain == "" || net.ParseIP(domain) != nil {
		return
	}
	parsed := net.ParseIP(canonicalIP)
	if !isCloudflareAnycast(parsed) {
		return
	}
	var rnd [2]byte
	GlobalPrivacy.FillCryptoRandom(rnd[:])
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
		// Step 1: Silent verification probe with a disposable CSPRNG ClientHello
		probeCtx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
		defer cancel()
		d := NewBoundDialer(r.binder, link, 400*time.Millisecond)
		probeConn, err := d.DialContext(probeCtx, "tcp", net.JoinHostPort(cloakIP, "443"))
		if err != nil || probeConn == nil {
			return
		}
		probePkt := BuildProbeClientHello(domain)
		_ = probeConn.SetDeadline(time.Now().Add(350 * time.Millisecond))
		_, wErr := probeConn.Write(probePkt)
		var hdr [5]byte
		rn, rErr := probeConn.Read(hdr[:])
		_ = probeConn.Close()
		if wErr != nil || rErr != nil || rn < 3 || hdr[0] != 0x16 {
			// Candidate cloak IP rejected the SNI (e.g. TLS Alert 0x15); discard it
			// so the user's real connection NEVER hits an alert or replays its nonce!
			return
		}
		// Step 2: Candidate cloak IP is verified to serve `domain`! Open a clean,
		// 0-byte socket and place it into warmPool under canonicalIP.
		warmCtx, wCancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer wCancel()
		cleanConn, err := d.DialContext(warmCtx, "tcp", net.JoinHostPort(cloakIP, "443"))
		if err != nil || cleanConn == nil {
			return
		}
		if tc, ok := cleanConn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		armKeepAlive(cleanConn)
		PutWarmConn(link, canonicalIP, "443", cleanConn)
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
	// 1. Try RFC 9230 Oblivious DoH (HPKE X25519 + AES-128-GCM) first:
	if ips := r.queryODoHOnLink(ctx, wireReq, txID, link); len(ips) > 0 {
		return ips
	}
	// 2. Zero-latency fallback to sharded, EDNS0-padded DoH providers:
	providers := dohProvidersWiFi
	if link == LinkCellular {
		providers = dohProvidersCell
	}
	if len(providers) == 0 {
		return nil
	}
	start := int(r.dohNext.Add(1) % uint64(len(providers)))
	// Generate randomized HTTP/2 header padding so DoH frame lengths are
	// decorrelated across queries even if HPACK compresses standard headers.
	var padRnd [32]byte
	GlobalPrivacy.FillCryptoRandom(padRnd[:])
	padHeader := base64.RawURLEncoding.EncodeToString(padRnd[:8+int(padRnd[0]&0x0F)])
	for attempt := 0; attempt < len(providers); attempt++ {
		p := providers[(start+attempt)%len(providers)]
		client := r.dohClients[dohClientKey(link, p.url)]
		if client == nil {
			continue
		}
		// Per-provider 500ms cap: prevents a dead 5G HTTP/2 socket on attempt 0
		// from consuming the entire lookupOnLink budget!
		reqCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, p.url, bytes.NewReader(wireReq))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("X-Padding", padHeader)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			// CRITICAL: Immediately purge dead 5G HTTP/2 connections from the
			// transport pool so the next DNS query dials a fresh 4G socket!
			client.CloseIdleConnections()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		status := resp.StatusCode
		resp.Body.Close()
		cancel()
		if err != nil || status != http.StatusOK {
			client.CloseIdleConnections()
			continue
		}
		if ips := parseDNSResponsePacket(body, txID); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

// queryODoHOnLink seals the DNS wire query with RFC 9180 HPKE (X25519 + AES-128-GCM)
// and transmits it as an RFC 9230 application/oblivious-dns-message.
func (r *VIPResolver) queryODoHOnLink(ctx context.Context, wireReq []byte, txID uint16, link LinkType) []net.IP {
	GlobalODoH.mu.RLock()
	proxyURL := GlobalODoH.proxyURL
	cfg := GlobalODoH.targetCfg
	targetHost := GlobalODoH.targetHost
	targetPath := GlobalODoH.targetPath
	GlobalODoH.mu.RUnlock()

	// Do not block DNS lookups if ODoH proxy or target key is not configured yet.
	if proxyURL == "" || cfg == nil {
		return nil
	}
	odohReq, cctx, err := cfg.SealQuery(wireReq)
	if err != nil {
		return nil
	}
	endpointURL := "https://1.1.1.1/dns-query"
	if link == LinkCellular {
		endpointURL = "https://[2606:4700:4700::1111]/dns-query"
	}
	client := r.dohClients[dohClientKey(link, endpointURL)]
	if client == nil {
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, 450*time.Millisecond)
	defer cancel()
	reqURL := proxyURL + "?targethost=" + targetHost + "&targetpath=" + targetPath
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, reqURL, bytes.NewReader(odohReq))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	resp, err := client.Do(req)
	if err != nil {
		client.CloseIdleConnections()
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	status := resp.StatusCode
	resp.Body.Close()
	if err != nil || status != http.StatusOK {
		return nil
	}
	dnsResp, err := cctx.OpenResponse(body)
	if err != nil {
		return nil
	}
	return parseDNSResponsePacket(dnsResp, txID)
}
func (r *VIPResolver) queryUDPOnLink(ctx context.Context, domain string, qtype uint16, link LinkType) []net.IP {
	if ips := r.queryDoHOnLink(ctx, domain, qtype, link); len(ips) > 0 {
		return ips
	}
	return nil
}

func buildDNSQueryPacket(domain string, qtype uint16, padEDNS bool) ([]byte, uint16) {
	var randBytes [2]byte
	GlobalPrivacy.FillCryptoRandom(randBytes[:])
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
