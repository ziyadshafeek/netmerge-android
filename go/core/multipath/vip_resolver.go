package multipath

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	firstVIP      uint32 = 0xC6120001 // 198.18.0.1
	vipsPerDomain int    = 4          // Rotating VIP ring per domain to defeat HTTP/2 coalescing
)

type DualEndpoint struct {
	Domain   string
	mu       sync.RWMutex
	WiFiAddr string
	CellAddr string
	Updated  time.Time
	readyCh  chan struct{}
	once     sync.Once
}

func (ep *DualEndpoint) markReady() {
	ep.once.Do(func() {
		if ep.readyCh != nil {
			close(ep.readyCh)
		}
	})
}

func (ep *DualEndpoint) WaitReady(ctx context.Context) (wifiAddr, cellAddr string) {
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

func (ep *DualEndpoint) Addrs() (wifiAddr, cellAddr string) {
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

	binder  SocketBinder
	resolve func(ctx context.Context, domain string) (wifiAddr, cellAddr string)
}

func NewVIPResolver(binder SocketBinder) *VIPResolver {
	r := &VIPResolver{
		vipToDom: make(map[uint32]*DualEndpoint),
		domToVIP: make(map[string]*domainVIPRing),
		binder:   binder,
	}
	r.nextVIP.Store(firstVIP)
	return r
}

// GetOrAllocateVIP allocates a ring of synthetic VIPs immediately (<0.1ms)
// and resolves the real per-link addresses asynchronously if not unit-tested.
// Rotating through the domain's VIP ring prevents HTTP/2 from coalescing
// parallel streams onto a single TCP connection.
func (r *VIPResolver) GetOrAllocateVIP(ctx context.Context, domain string) (net.IP, *DualEndpoint) {
	r.mu.RLock()
	if ring, ok := r.domToVIP[domain]; ok {
		r.mu.RUnlock()
		pick := ring.vips[ring.idx.Add(1)%uint32(vipsPerDomain)]
		// Trigger background refresh if older than 2 minutes
		w, c := ring.ep.Addrs()
		if (w == "" && c == "") || time.Since(ring.ep.Updated) > 2*time.Minute {
			go r.populateEndpoint(ring.ep)
		}
		return vipFromInt(pick), ring.ep
	}
	r.mu.RUnlock()

	// If unit test hook is set, resolve synchronously to preserve test behavior
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
		defer r.mu.Unlock()
		if ring, ok := r.domToVIP[domain]; ok {
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
		ring := &domainVIPRing{ep: ep}
		for i := 0; i < vipsPerDomain; i++ {
			v := r.nextVIP.Add(1)
			ring.vips[i] = v
			r.vipToDom[v] = ep
		}
		r.domToVIP[domain] = ring
		return vipFromInt(ring.vips[0]), ep
	}

	// Production path: allocate VIP ring immediately (0ms DNS latency!)
	// and fire parallel resolution on Wi-Fi + Cellular.
	r.mu.Lock()
	if ring, ok := r.domToVIP[domain]; ok {
		r.mu.Unlock()
		pick := ring.vips[ring.idx.Add(1)%uint32(vipsPerDomain)]
		return vipFromInt(pick), ring.ep
	}
	ep := &DualEndpoint{
		Domain:  domain,
		Updated: time.Now(),
		readyCh: make(chan struct{}),
	}
	ring := &domainVIPRing{ep: ep}
	for i := 0; i < vipsPerDomain; i++ {
		v := r.nextVIP.Add(1)
		ring.vips[i] = v
		r.vipToDom[v] = ep
	}
	r.domToVIP[domain] = ring
	r.mu.Unlock()

	go r.populateEndpoint(ep)

	// Wait briefly (up to 80ms) so fast DNS already has IPs populated,
	// but never block DNS responses for seconds!
	select {
	case <-ep.readyCh:
	case <-time.After(80 * time.Millisecond):
	}
	return vipFromInt(ring.vips[0]), ep
}

func (r *VIPResolver) populateEndpoint(ep *DualEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Wi-Fi resolution: race 8.8.8.8 and 1.1.1.1 over IPv4
	go func() {
		defer wg.Done()
		ip := r.resolveFast(ctx, ep.Domain, LinkWiFi, []string{"8.8.8.8:53", "1.1.1.1:53"}, "ip4")
		if ip != "" {
			ep.mu.Lock()
			ep.WiFiAddr = ip
			if ep.CellAddr == "" {
				ep.CellAddr = ip
			}
			ep.Updated = time.Now()
			ep.mu.Unlock()
			ep.markReady()
		}
	}()

	// Cellular resolution: race IPv6 DNS (for both AAAA and A!) + NAT64 DNS + IPv4 DNS
	go func() {
		defer wg.Done()
		cellServers := []string{
			"[2001:4860:4860::8888]:53",
			"[2606:4700:4700::1111]:53",
			"[64:ff9b::808:808]:53",
			"8.8.8.8:53",
		}
		// Prefer IPv4 A record (works universally across both links and via NAT64),
		// fallback to AAAA if IPv6-only target.
		ip := r.resolveFast(ctx, ep.Domain, LinkCellular, cellServers, "ip4")
		if ip == "" {
			ip = r.resolveFast(ctx, ep.Domain, LinkCellular, cellServers, "ip6")
		}
		if ip != "" {
			ep.mu.Lock()
			ep.CellAddr = ip
			if ep.WiFiAddr == "" && net.ParseIP(ip).To4() != nil {
				ep.WiFiAddr = ip
			}
			ep.Updated = time.Now()
			ep.mu.Unlock()
			ep.markReady()
		}
	}()

	wg.Wait()
	ep.markReady()
}

func (r *VIPResolver) resolveFast(ctx context.Context, domain string, link LinkType, servers []string, ipNet string) string {
	resCh := make(chan string, len(servers))
	rctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	for _, srv := range servers {
		go func(dnsServer string) {
			dialer := NewBoundDialer(r.binder, link, 1000*time.Millisecond)
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(dctx context.Context, network, address string) (net.Conn, error) {
					return dialer.DialContext(dctx, "udp", dnsServer)
				},
			}
			ips, err := resolver.LookupIP(rctx, ipNet, domain)
			if err == nil && len(ips) > 0 {
				resCh <- ips[0].String()
				return
			}
			resCh <- ""
		}(srv)
	}

	for i := 0; i < len(servers); i++ {
		select {
		case ip := <-resCh:
			if ip != "" {
				return ip
			}
		case <-rctx.Done():
			return ""
		}
	}
	return ""
}

func (r *VIPResolver) EndpointForVIP(ip net.IP) *DualEndpoint {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.vipToDom[binary.BigEndian.Uint32(ip4)]
}

func vipFromInt(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
