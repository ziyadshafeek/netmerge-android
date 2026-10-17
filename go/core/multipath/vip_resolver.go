package multipath

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// firstVIP is 198.18.0.1. Synthetic VIPs come from RFC 2544 benchmarking
// space (198.18.0.0/15), which is guaranteed unroutable on the public
// internet, so a VIP can never collide with a real destination address.
const firstVIP uint32 = 0xC6120001 // 198.18.0.1

// DualEndpoint holds the per-link native endpoints for one hostname: the
// address each physical link should use to fetch the same resource. On
// Jio (IPv6-first) the cellular address is the native IPv6 CDN edge, while
// Wi-Fi uses the IPv4 edge — talking to each CDN over its native family
// avoids the congested 464XLAT path.
type DualEndpoint struct {
	Domain   string
	WiFiAddr string // prefer IPv4 (Wi-Fi/CDN edge)
	CellAddr string // prefer native IPv6 (Jio), fallback IPv4 via 464XLAT
	Updated  time.Time
}

// VIPResolver maps hostnames to synthetic VIPs and resolves the native
// per-link endpoints behind them. The app is told the VIP (so HTTP/2
// connection coalescing can't merge subdomains onto one socket), while the
// data plane dials the real per-link addresses. Safe for concurrent use.
type VIPResolver struct {
	mu       sync.RWMutex
	vipToDom map[uint32]*DualEndpoint
	domToVIP map[string]uint32
	nextVIP  atomic.Uint32

	binder SocketBinder

	// resolve overrides live DNS when non-nil (unit tests).
	resolve func(ctx context.Context, domain string) (wifiAddr, cellAddr string)
}

// NewVIPResolver creates a resolver whose DNS queries are bound to the
// physical links via binder.
func NewVIPResolver(binder SocketBinder) *VIPResolver {
	r := &VIPResolver{
		vipToDom: make(map[uint32]*DualEndpoint),
		domToVIP: make(map[string]uint32),
		binder:   binder,
	}
	r.nextVIP.Store(firstVIP)
	return r
}

// GetOrAllocateVIP returns the synthetic VIP for domain, allocating and
// resolving it on first use. DNS resolution runs concurrently per link; a
// failed lookup still allocates (with empty addresses) so the caller never
// blocks on DNS. Concurrent calls for the same domain return the same VIP.
func (r *VIPResolver) GetOrAllocateVIP(ctx context.Context, domain string) (net.IP, *DualEndpoint) {
	// Fast path: already allocated.
	r.mu.RLock()
	if v, ok := r.domToVIP[domain]; ok {
		ep := r.vipToDom[v]
		r.mu.RUnlock()
		return vipFromInt(v), ep
	}
	r.mu.RUnlock()

	wifiAddr, cellAddr := r.resolveAddrs(ctx, domain)

	// Slow path: allocate under the write lock, re-checking for a lost race.
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.domToVIP[domain]; ok {
		return vipFromInt(v), r.vipToDom[v]
	}
	v := r.nextVIP.Add(1)
	ep := &DualEndpoint{
		Domain:   domain,
		WiFiAddr: wifiAddr,
		CellAddr: cellAddr,
		Updated:  time.Now(),
	}
	r.domToVIP[domain] = v
	r.vipToDom[v] = ep
	return vipFromInt(v), ep
}

// EndpointForVIP returns the dual endpoint behind a synthetic VIP, or nil
// if ip is not one of ours. The data plane uses this to translate the
// app's VIP connection back to the real per-link addresses.
func (r *VIPResolver) EndpointForVIP(ip net.IP) *DualEndpoint {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.vipToDom[binary.BigEndian.Uint32(ip4)]
}

// resolveAddrs resolves domain on both links, concurrently.
func (r *VIPResolver) resolveAddrs(ctx context.Context, domain string) (wifiAddr, cellAddr string) {
	if r.resolve != nil {
		return r.resolve(ctx, domain)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Wi-Fi: IPv4 edge via public DNS.
		wifiAddr = r.resolveOnLink(ctx, domain, LinkWiFi, "8.8.8.8:53", false)
	}()
	go func() {
		defer wg.Done()
		// Cellular: native IPv6 first (Jio's fast path), then IPv4 via 464XLAT.
		cellAddr = r.resolveOnLink(ctx, domain, LinkCellular, "[2001:4860:4860::8888]:53", true)
		if cellAddr == "" {
			cellAddr = r.resolveOnLink(ctx, domain, LinkCellular, "8.8.8.8:53", false)
		}
	}()
	wg.Wait()
	return wifiAddr, cellAddr
}

// resolveOnLink resolves domain to a single address using dnsServer, with
// the DNS query itself bound to link via the SocketBinder. preferV6 asks
// for AAAA records; otherwise A records.
func (r *VIPResolver) resolveOnLink(ctx context.Context, domain string, link LinkType, dnsServer string, preferV6 bool) string {
	dialer := NewBoundDialer(r.binder, link, 2*time.Second)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", dnsServer)
		},
	}
	ipNet := "ip4"
	if preferV6 {
		ipNet = "ip6"
	}
	// Bound the lookup so a dead link can't stall VIP allocation.
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(lctx, ipNet, domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

// vipFromInt converts a VIP counter value to a 4-byte IP.
func vipFromInt(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
