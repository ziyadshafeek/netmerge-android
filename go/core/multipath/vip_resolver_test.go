package multipath

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubResolver returns a resolver whose DNS is faked: no network needed.
func stubResolver(wifi, cell string) *VIPResolver {
	r := NewVIPResolver(nil)
	r.resolve = func(ctx context.Context, domain string) (string, string) {
		return wifi, cell
	}
	return r
}

func inBenchmarkNet(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func TestVIPAllocationIncrements(t *testing.T) {
	r := stubResolver("1.2.3.4", "2409::1")

	ip1, _ := r.GetOrAllocate(context.Background(), "a.example")
	ip2, _ := r.GetOrAllocate(context.Background(), "b.example")

	if !inBenchmarkNet(ip1) || !inBenchmarkNet(ip2) {
		t.Fatalf("VIPs outside 198.18.0.0/15: %v %v", ip1, ip2)
	}
	if ip1.Equal(ip2) {
		t.Fatalf("distinct domains got same VIP %v", ip1)
	}
	// Counter starts at 0xC6120001; each domain allocates a ring of 8 VIPs.
	// a.example -> .1-.8 (returns .1); b.example -> .9-.16 (returns .9).
	if ip1.String() != "198.18.0.1" || ip2.String() != "198.18.0.9" {
		t.Fatalf("expected 198.18.0.1, 198.18.0.9; got %v, %v", ip1, ip2)
	}
}

func TestSameDomainSameVIP(t *testing.T) {
	r := stubResolver("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")

	ip1, ep1 := r.GetOrAllocate(context.Background(), "example.com")
	ip2, ep2 := r.GetOrAllocate(context.Background(), "example.com")

	// VIP ring: consecutive queries rotate through alias VIPs (all in
	// 198.18.0.0/15) pointing at the SAME DualEndpoint.
	if !inBenchmarkNet(ip1) || !inBenchmarkNet(ip2) {
		t.Fatalf("VIPs outside 198.18.0.0/15: %v %v", ip1, ip2)
	}
	if ep1 != ep2 {
		t.Fatalf("same domain got different endpoints: %+v vs %+v", ep1, ep2)
	}
	if ep1.Domain != "example.com" || ep2.Domain != "example.com" {
		t.Fatalf("endpoint domain wrong: %+v %+v", ep1, ep2)
	}
	if ep1.WiFiAddr != "93.184.216.34" || ep1.CellAddr != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Fatalf("endpoint addrs wrong: %+v", ep1)
	}
	if ep1.Updated.IsZero() {
		t.Fatal("endpoint Updated not set")
	}
	// After 10 queries the ring should have 8 distinct alias VIPs.
	seen := map[string]bool{ip1.String(): true, ip2.String(): true}
	for i := 0; i < 10; i++ {
		ip, _ := r.GetOrAllocate(context.Background(), "example.com")
		seen[ip.String()] = true
	}
	if len(seen) != 8 {
		t.Fatalf("expected 8 alias VIPs in ring, got %d: %v", len(seen), seen)
	}
}

func TestConcurrentAllocationNoDuplicates(t *testing.T) {
	r := NewVIPResolver(nil)
	// Slow the stub to widen the race window on the allocate path.
	r.resolve = func(ctx context.Context, domain string) (string, string) {
		time.Sleep(5 * time.Millisecond)
		return "10.0.0.1", "fd00::1"
	}

	const workers = 64
	var wg sync.WaitGroup
	results := make([]net.IP, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip, _ := r.GetOrAllocate(context.Background(), "race.example")
			results[i] = ip
		}(i)
	}
	// Meanwhile allocate a few distinct domains too.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.GetOrAllocate(context.Background(), fmt.Sprintf("d%d.example", i))
		}(i)
	}
	wg.Wait()

	// Concurrent callers for the same domain rotate through its 8-VIP ring
	// (anti-coalescing), but every VIP must resolve to the SAME endpoint.
	wantEP, ok := r.LookupVIP(results[0])
	if !ok || wantEP.Domain != "race.example" {
		t.Fatalf("LookupVIP(%v) = %+v, want race.example", results[0], wantEP)
	}
	seen := map[string]bool{}
	for i := 0; i < workers; i++ {
		if results[i] == nil || !inBenchmarkNet(results[i]) {
			t.Fatalf("worker %d got bad VIP %v", i, results[i])
		}
		if got, ok := r.LookupVIP(results[i]); !ok || got != wantEP {
			t.Fatalf("worker %d VIP %v resolved to %+v, want same endpoint", i, results[i], got)
		}
		seen[results[i].String()] = true
	}
	if len(seen) > 8 {
		t.Fatalf("expected at most 8 alias VIPs in ring, got %d: %v", len(seen), seen)
	}

	// 1 shared + 8 distinct domains => exactly 9 VIPs allocated.
	r.mu.RLock()
	n := len(r.domToVIP)
	r.mu.RUnlock()
	if n != 9 {
		t.Fatalf("expected 9 distinct VIPs, got %d", n)
	}
}

func TestEndpointForVIP(t *testing.T) {
	r := stubResolver("1.1.1.1", "::1")
	ip, _ := r.GetOrAllocate(context.Background(), "lookup.example")

	ep, ok := r.LookupVIP(ip)
	if !ok || ep.Domain != "lookup.example" {
		t.Fatalf("LookupVIP(%v) = %+v, want lookup.example", ip, ep)
	}
	if _, ok := r.LookupVIP(net.ParseIP("8.8.8.8")); ok {
		t.Fatalf("LookupVIP(8.8.8.8) succeeded, want miss")
	}
	if _, ok := r.LookupVIP(net.ParseIP("2001:db8::1")); ok {
		t.Fatalf("LookupVIP(v6) succeeded, want miss")
	}
}

// fakeBinder records BindAndProtect calls and can be told to fail.
type fakeBinder struct {
	calls atomic.Int64
	fail  atomic.Bool
	link  atomic.Int64
}

func (f *fakeBinder) BindAndProtect(fd int64, networkType int) bool {
	f.calls.Add(1)
	f.link.Store(int64(networkType))
	return !f.fail.Load()
}

func (f *fakeBinder) CanBindLink(networkType int) bool {
	return !f.fail.Load()
}

func (f *fakeBinder) OnBytes(networkType int, rxBytes, txBytes int64) {}

func TestBoundDialerUsesBinder(t *testing.T) {
	fb := &fakeBinder{}
	d := NewBoundDialer(fb, LinkCellular, 2*time.Second)

	// UDP dial to localhost: Control runs before connect; no packet needed.
	c, err := d.DialContext(context.Background(), "udp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	c.Close()

	if fb.calls.Load() != 1 {
		t.Fatalf("binder called %d times, want 1", fb.calls.Load())
	}
	if got := LinkType(fb.link.Load()); got != LinkCellular {
		t.Fatalf("binder got link %v, want LinkCellular", got)
	}
}

func TestBoundDialerBinderFailureAborts(t *testing.T) {
	fb := &fakeBinder{}
	fb.fail.Store(true)
	d := NewBoundDialer(fb, LinkWiFi, 2*time.Second)

	if _, err := d.DialContext(context.Background(), "udp", "127.0.0.1:1"); err == nil {
		t.Fatal("expected dial to fail when binder refuses, got nil error")
	}
}
