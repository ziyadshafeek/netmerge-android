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
// vipRingSize is the max number of alias VIPs per domain. Rotating VIPs
// across DNS queries prevents Chrome/Cronet from coalescing separate
// sub-resources onto a single TCP socket, multiplying parallel streams.
const vipRingSize = 4

type VIPResolver struct {
	mu       sync.RWMutex
	vipToDom map[uint32]*DualEndpoint
	domToVIP map[string][]uint32 // ring of alias VIPs per domain
	domRR    map[string]uint64   // round-robin cursor per domain
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
		domToVIP: make(map[string][]uint32),
		domRR:    make(map[string]uint64),
		binder:   binder,
	}
	r.nextVIP.Store(firstVIP)
	return r
}

// GetOrAllocateVIP returns the synthetic VIP for domain, allocating and
// resolving it on first use. DNS resolution runs concurrently per link; a
// failed lookup still allocates (with empty addresses) so the caller never
// blocks on DNS. Concurrent calls for the same domain rotate through a ring
// of up to 4 alias VIPs (all pointing at the same DualEndpoint), defeating
// HTTP/2 connection coalescing. Zero added DNS latency after first resolve.
func (r *VIPResolver) GetOrAllocateVIP(ctx context.Context, domain string) (net.IP, *DualEndpoint) {
	// Fast path: already allocated — rotate through the VIP ring.
	r.mu.Lock()
	if vips, ok := r.domToVIP[domain]; ok && len(vips) > 0 {
		ep := r.vipToDom[vips[0]]
		// Grow the ring up to vipRingSize with alias VIPs on the same endpoint.
		if len(vips) < vipRingSize && ep != nil {
			v := r.nextVIP.Add(1)
			r.vipToDom[v] = ep
			vips = append(vips, v)
			r.domToVIP[domain] = vips
		}
		rr := r.domRR[domain]
		r.domRR[domain] = rr + 1
		v := vips[rr%uint64(len(vips))]
		ep = r.vipToDom[v]
		r.mu.Unlock()
		return vipFromInt(v), ep
	}
	r.mu.Unlock()

	wifiAddr, cellAddr := r.resolveAddrs(ctx, domain)

	// Never cache a completely empty endpoint — it blackholes all traffic
	// to this domain forever. If one side resolved, copy it as fallback.
	if wifiAddr == "" && cellAddr == "" {
		return nil, nil
	}
	if wifiAddr == "" {
		wifiAddr = cellAddr
	}
	if cellAddr == "" {
		cellAddr = wifiAddr
	}

	// Slow path: allocate under the write lock, re-checking for a lost race.
	r.mu.Lock()
	defer r.mu.Unlock()
	if vips, ok := r.domToVIP[domain]; ok && len(vips) > 0 {
		rr := r.domRR[domain]
		r.domRR[domain] = rr + 1
		v := vips[rr%uint64(len(vips))]
		return vipFromInt(v), r.vipToDom[v]
	}
	v := r.nextVIP.Add(1)
	ep := &DualEndpoint{
		Domain:   domain,
		WiFiAddr: wifiAddr,
		CellAddr: cellAddr,
		Updated:  time.Now(),
	}
	r.domToVIP[domain] = []uint32{v}
	r.domRR[domain] = 1 // next query rotates to alias VIP #2 (allocated above)
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
// It returns as soon as the FIRST link succeeds (plus a 200ms grace for the
// second), so a slow/dead link never stalls VIP allocation past Chrome's ~1s
// DNS timeout. The slower link's result updates the endpoint in the background.
func (r *VIPResolver) resolveAddrs(ctx context.Context, domain string) (wifiAddr, cellAddr string) {
	if r.resolve != nil {
		return r.resolve(ctx, domain)
	}
	type res struct {
		link LinkType
		addr string
	}
	ch := make(chan res, 2)
	go func() {
		// Wi-Fi: IPv4 edge via public DNS.
		ch <- res{LinkWiFi, r.resolveOnLink(ctx, domain, LinkWiFi, "8.8.8.8:53", false)}
	}()
	go func() {
		// Cellular: native IPv6 first (Jio's fast path), then IPv4 via 464XLAT.
		addr := r.resolveOnLink(ctx, domain, LinkCellular, "[2001:4860:4860::8888]:53", true)
		if addr == "" {
			addr = r.resolveOnLink(ctx, domain, LinkCellular, "8.8.8.8:53", false)
		}
		ch <- res{LinkCellular, addr}
	}()

	// Wait for the first result, then give the slower link a 200ms grace.
	// A missing side is backfilled by GetOrAllocateVIP's copy-fallback.
	timeout := time.After(1500 * time.Millisecond)
	var grace <-chan time.Time // armed only after the first link succeeds
	got := 0
	for got < 2 {
		select {
		case rr := <-ch:
			if rr.link == LinkWiFi {
				wifiAddr = rr.addr
			} else {
				cellAddr = rr.addr
			}
			got++
			if got == 1 {
				// First link done; start grace period for the second.
				grace = time.After(200 * time.Millisecond)
			} else {
				return wifiAddr, cellAddr
			}
		case <-grace:
			return wifiAddr, cellAddr
		case <-timeout:
			return wifiAddr, cellAddr
		case <-ctx.Done():
			return wifiAddr, cellAddr
		}
	}
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
			// Try the DNS server as-is first.
			c, err := dialer.DialContext(ctx, "udp", dnsServer)
			if err == nil {
				return c, nil
			}
			// NAT64 fallback: if dnsServer is IPv4 and we're on cellular
			// (likely IPv6-only like Jio), retry via 64:ff9b::/96.
			if link == LinkCellular {
				if host, port, serr := net.SplitHostPort(dnsServer); serr == nil {
					if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
						nat64 := net.JoinHostPort(toNAT64(ip), port)
						return dialer.DialContext(ctx, "udp", nat64)
					}
				}
			}
			return nil, err
		},
	}
	ipNet := "ip4"
	if preferV6 {
		ipNet = "ip6"
	}
	// Bound the lookup so a dead link can't stall VIP allocation.
	// 1200ms: Chrome gives up on DNS after ~1s, so we must be faster.
	lctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
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
