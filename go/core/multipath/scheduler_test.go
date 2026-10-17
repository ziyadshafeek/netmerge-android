package multipath

import "testing"

// Regression test for the Wi-Fi starvation bug: the old SelectLinks evaluated
// actualCellShare before the idle-link wakeup branches, making the Wi-Fi wakeup
// branch unreachable for the first flows (everything pinned to Cellular).
func TestSelectLinksIdleWakeup(t *testing.T) {
	s := NewScheduler()

	// Flow 1 from idle: seq=1 (odd), cellular prior (56Mbps) > wifi prior
	// (40Mbps) -> cellular wakes first.
	p, _, _ := s.SelectLinks(1024)
	if p != LinkCellular {
		t.Fatalf("flow 1: got primary %v, want Cellular", p)
	}
	s.AcquireFlow(LinkCellular)

	// Flow 2: Wi-Fi idle while Cellular active -> MUST go to Wi-Fi
	// (this was the unreachable dead-code branch).
	p, _, _ = s.SelectLinks(1024)
	if p != LinkWiFi {
		t.Fatalf("flow 2: got primary %v, want WiFi (idle-link wakeup)", p)
	}
	s.AcquireFlow(LinkWiFi)

	// Flow 3: both active; cellular share 0.5 < target ~0.58 -> cellular.
	p, _, _ = s.SelectLinks(1024)
	if p != LinkCellular {
		t.Fatalf("flow 3: got primary %v, want Cellular", p)
	}
	s.AcquireFlow(LinkCellular)

	// Flow 4: cellular share 2/3=0.67 >= target, wifi share 0.33 < 0.42 -> wifi.
	// Key assertion: Wi-Fi is NOT starved; both links get flows.
	p, _, _ = s.SelectLinks(1024)
	if p != LinkWiFi {
		t.Fatalf("flow 4: got primary %v, want WiFi (share rebalancing)", p)
	}

	for _, l := range []LinkType{LinkWiFi, LinkCellular, LinkCellular} {
		s.ReleaseFlow(l)
	}
}

// Stagger sanity: cellular-primary assignments must carry a real head start
// (>=260ms) so 5G NR survives Wi-Fi's shorter RTT; wifi-primary stays small.
func TestSelectLinksStaggerBounds(t *testing.T) {
	s := NewScheduler()
	for i := 0; i < 20; i++ {
		p, _, stagger := s.SelectLinks(256 * 1024)
		if p == LinkCellular && stagger < 260_000_000 {
			t.Fatalf("cellular primary with stagger %v < 260ms", stagger)
		}
		if p == LinkWiFi && (stagger < 140_000_000 || stagger > 280_000_000) {
			t.Fatalf("wifi primary with stagger %v outside [140ms, 280ms]", stagger)
		}
		// Simulate the flow so ratios evolve.
		s.AcquireFlow(p)
	}
}
