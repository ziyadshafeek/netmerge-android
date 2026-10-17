package multipath

import (
	"testing"
	"time"
)

func TestMiceFlowsNeverEvicted(t *testing.T) {
	g := NewElephantQUICGuard()
	// 100 packets of 10KB = 1MB total, well under the 2.5MB threshold.
	for i := 0; i < 100; i++ {
		if g.OnUDPPacket("flow-mice", 1000, "142.250.1.1", 443, 10*1024, true) {
			t.Fatalf("mice flow evicted at packet %d", i)
		}
	}
	g.mu.RLock()
	tr := g.flows["flow-mice"]
	g.mu.RUnlock()
	if tr != nil && tr.Evicted.Load() {
		t.Fatal("mice flow marked evicted")
	}
}

func TestNonQUICPortIgnored(t *testing.T) {
	g := NewElephantQUICGuard()
	// 10MB over UDP/53 (DNS): must never be evicted, port != 443.
	for i := 0; i < 1000; i++ {
		if g.OnUDPPacket("flow-dns", 1000, "8.8.8.8", 53, 10*1024, true) {
			t.Fatal("non-443 flow evicted")
		}
	}
	if g.ShouldBlockNewQUIC(1000, "8.8.8.8", 53) {
		t.Fatal("ShouldBlockNewQUIC true for port 53")
	}
	if g.ShouldBlockNewQUIC(1000, "8.8.8.8", 443) {
		t.Fatal("ShouldBlockNewQUIC true with no cooldown")
	}
}

func TestElephantFlowEvicted(t *testing.T) {
	g := NewElephantQUICGuard()
	// Backdate the flow start so the rate/age gates pass deterministically:
	// 3MB transferred over 2s = 1.5MB/s >> 500KB/s threshold.
	g.OnUDPPacket("flow-big", 1000, "142.250.1.2", 443, 1024, true)
	g.mu.Lock()
	g.flows["flow-big"].StartTime = time.Now().Add(-2 * time.Second)
	g.mu.Unlock()

	evicted := false
	for i := 0; i < 3000 && !evicted; i++ {
		evicted = g.OnUDPPacket("flow-big", 1000, "142.250.1.2", 443, 1024, true)
	}
	if !evicted {
		t.Fatal("elephant flow (3MB @ 1.5MB/s) was not evicted")
	}
	// Exactly-once semantics: further packets must not re-evict.
	if g.OnUDPPacket("flow-big", 1000, "142.250.1.2", 443, 64*1024, true) {
		t.Fatal("second eviction for the same flow")
	}
	// Cooldown must now block new QUIC to the same destination.
	if !g.ShouldBlockNewQUIC(1000, "142.250.1.2", 443) {
		t.Fatal("cooldown did not block new QUIC after eviction")
	}
	// ...but not other destinations or other UIDs.
	if g.ShouldBlockNewQUIC(1000, "142.250.1.3", 443) {
		t.Fatal("cooldown leaked to a different destination")
	}
	if g.ShouldBlockNewQUIC(2000, "142.250.1.2", 443) {
		t.Fatal("cooldown leaked to a different UID")
	}
}

func TestNoEvictWhenSecondaryBusy(t *testing.T) {
	g := NewElephantQUICGuard()
	g.OnUDPPacket("flow-busy", 1000, "142.250.1.4", 443, 1024, false)
	g.mu.Lock()
	g.flows["flow-busy"].StartTime = time.Now().Add(-2 * time.Second)
	g.mu.Unlock()
	// secondaryLinkIdle=false: 5MB must still not trigger eviction.
	for i := 0; i < 5000; i++ {
		if g.OnUDPPacket("flow-busy", 1000, "142.250.1.4", 443, 1024, false) {
			t.Fatal("evicted while secondary link was busy")
		}
	}
}

func TestSlowFlowNotEvicted(t *testing.T) {
	g := NewElephantQUICGuard()
	// 3MB over 60s = 50KB/s, far under the 500KB/s rate threshold.
	g.OnUDPPacket("flow-slow", 1000, "142.250.1.5", 443, 1024, true)
	g.mu.Lock()
	g.flows["flow-slow"].StartTime = time.Now().Add(-60 * time.Second)
	g.mu.Unlock()
	for i := 0; i < 3000; i++ {
		if g.OnUDPPacket("flow-slow", 1000, "142.250.1.5", 443, 1024, true) {
			t.Fatal("slow trickle flow evicted despite low rate")
		}
	}
}

func TestCooldownExpires(t *testing.T) {
	g := NewElephantQUICGuard()
	// Seed an expired cooldown directly.
	k := g.key(1000, "142.250.1.6", 443)
	g.mu.Lock()
	g.cooldowns[k] = time.Now().Add(-time.Second)
	g.mu.Unlock()

	if g.ShouldBlockNewQUIC(1000, "142.250.1.6", 443) {
		t.Fatal("expired cooldown still blocks")
	}
	if n := g.CooldownCount(); n != 0 {
		t.Fatalf("expired cooldown not cleaned, count=%d", n)
	}
}

func TestCleanupDropsStaleFlows(t *testing.T) {
	g := NewElephantQUICGuard()
	g.OnUDPPacket("flow-stale", 1000, "142.250.1.7", 443, 1024, true)
	g.mu.Lock()
	g.flows["flow-stale"].LastSeen = time.Now().Add(-10 * time.Minute)
	k := g.key(1000, "142.250.1.8", 443)
	g.cooldowns[k] = time.Now().Add(-time.Second)
	g.mu.Unlock()

	g.Cleanup()
	if n := g.FlowCount(); n != 0 {
		t.Fatalf("stale flow not cleaned, count=%d", n)
	}
	if n := g.CooldownCount(); n != 0 {
		t.Fatalf("expired cooldown not cleaned, count=%d", n)
	}
}
