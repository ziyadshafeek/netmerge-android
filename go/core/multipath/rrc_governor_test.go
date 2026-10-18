package multipath

import (
	"testing"
	"time"
)

func TestRRCGovernorNilSafe(t *testing.T) {
	var g *RRCPowerGovernor
	if !g.ShouldEngageCellular(1024) {
		t.Fatal("nil governor must engage cellular (fail-open)")
	}
	if g.State() != RRCIdle {
		t.Fatal("nil governor state should read as idle")
	}
}

func TestRRCGovernorNoScheduler(t *testing.T) {
	g := &RRCPowerGovernor{}
	if !g.ShouldEngageCellular(1024) {
		t.Fatal("governor without scheduler must engage cellular (fail-open)")
	}
}

func TestRRCGovernorWakePulseRateLimit(t *testing.T) {
	g := InitRRCGovernor(nil, nil)
	// Binder is nil; triggerNonBlockingWakePulse should still rate-limit safely.
	g.triggerNonBlockingWakePulse()
	first := g.lastWakePulseNs.Load()
	if first == 0 {
		t.Fatal("wake pulse timestamp not recorded")
	}
	g.triggerNonBlockingWakePulse()
	if g.lastWakePulseNs.Load() != first {
		t.Fatal("second pulse within 3s should be rate-limited")
	}
	// Reset global to avoid cross-test interference.
	GlobalRRCGovernor = nil
	_ = time.Second
}
