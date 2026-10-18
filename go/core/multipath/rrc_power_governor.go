package multipath

import (
	"context"
	"sync/atomic"
	"time"
)

// RRCState models the 3GPP 5G NR / LTE modem power state without waking the
// radio when Wi-Fi alone can satisfy current traffic demand with zero
// bufferbloat.
type RRCState int32

const (
	RRCIdle         RRCState = 0 // cellular untouched; zero tail power
	RRCPreWake      RRCState = 1 // 1-byte UDP pulse sent; transitioning (~80ms)
	RRCActiveBond   RRCState = 2 // high BDP demand or Wi-Fi bloat; both radios bonding
	RRCTailCoalesce RRCState = 3 // cooldown; batching keepalives to let modem sleep
)

const (
	// WiFiBloatMultiplier triggers cellular wakeup when Wi-Fi SRTT exceeds 1.35x MinRTT.
	WiFiBloatMultiplier = 1.35
	// WiFiUtilWakeRatio wakes cellular when Wi-Fi live load > 65% of observed peak.
	WiFiUtilWakeRatio = 0.65
	// MinBurstBytesToWakeCellular prevents tiny background notifications from waking 5G NR.
	MinBurstBytesToWakeCellular = 128 * 1024
	// RRCInactivityTail is the idle duration after which cellular keepalives stop.
	RRCInactivityTail = 8 * time.Second
)

// RRCPowerGovernor decides whether the cellular radio should be engaged
// right now, saving battery during light browsing while waking 5G instantly
// on bursts or Wi-Fi bufferbloat.
type RRCPowerGovernor struct {
	state            atomic.Int32
	lastCellDemandNs atomic.Int64
	lastWakePulseNs  atomic.Int64
	binder           SocketBinder
	sched            *Scheduler
}

// GlobalRRCGovernor is the process-wide governor, initialised by NewRacer.
var GlobalRRCGovernor *RRCPowerGovernor

// InitRRCGovernor creates and publishes the process-wide RRC governor.
func InitRRCGovernor(binder SocketBinder, sched *Scheduler) *RRCPowerGovernor {
	g := &RRCPowerGovernor{binder: binder, sched: sched}
	g.state.Store(int32(RRCIdle))
	GlobalRRCGovernor = g
	return g
}

// State returns the current RRC power state.
func (g *RRCPowerGovernor) State() RRCState {
	if g == nil {
		return RRCIdle
	}
	return RRCState(g.state.Load())
}

// ShouldEngageCellular reports whether the cellular radio should be used for
// a transfer of expectedBytes right now.
func (g *RRCPowerGovernor) ShouldEngageCellular(expectedBytes int64) bool {
	if g == nil || g.sched == nil {
		return true
	}
	wStats := g.sched.Stats(LinkWiFi)
	cStats := g.sched.Stats(LinkCellular)
	// Always engage cellular if Wi-Fi is unhealthy or unbindable.
	if !wStats.Healthy || (g.binder != nil && !g.binder.CanBindLink(int(LinkWiFi))) {
		g.markDemand()
		return true
	}
	// Wi-Fi bufferbloat: SRTT > 1.35x MinRTT.
	wifiBloated := wStats.MinRTT > 0 && float64(wStats.SRTT) > float64(wStats.MinRTT)*WiFiBloatMultiplier
	// Wi-Fi saturation: live byte rate vs observed peak.
	wLiveRate := float64(rollingBytes[LinkWiFi].Load() * 5)
	wPeak := float64(peakRateBps[LinkWiFi].Load())
	wifiSaturated := wPeak > 256*1024 && wPeak > 0 && (wLiveRate/wPeak) >= WiFiUtilWakeRatio
	// Bulk demand: large transfer or many parallel flows.
	bulkDemand := expectedBytes >= MinBurstBytesToWakeCellular || wStats.ActiveFlows >= 4
	if wifiBloated || wifiSaturated || bulkDemand || cStats.ActiveFlows > 0 {
		g.markDemand()
		if g.State() == RRCIdle {
			g.state.Store(int32(RRCPreWake))
			g.triggerNonBlockingWakePulse()
		}
		g.state.Store(int32(RRCActiveBond))
		return true
	}
	// Tail window: keep cellular warm briefly so back-to-back requests don't flap RRC.
	if time.Since(time.Unix(0, g.lastCellDemandNs.Load())) < RRCInactivityTail {
		g.state.Store(int32(RRCTailCoalesce))
		return true
	}
	g.state.Store(int32(RRCIdle))
	return false
}

func (g *RRCPowerGovernor) markDemand() { g.lastCellDemandNs.Store(time.Now().UnixNano()) }

// triggerNonBlockingWakePulse sends a single 1-byte UDP packet on cellular to
// nudge the 5G NR modem from RRC_IDLE toward RRC_CONNECTED (~80ms) while
// Wi-Fi serves the first bytes of the burst. Rate-limited to one pulse/3s.
func (g *RRCPowerGovernor) triggerNonBlockingWakePulse() {
	now := time.Now().UnixNano()
	last := g.lastWakePulseNs.Load()
	if now-last < int64(3*time.Second) {
		return
	}
	if !g.lastWakePulseNs.CompareAndSwap(last, now) {
		return
	}
	go func() {
		d := NewBoundDialer(g.binder, LinkCellular, 800*time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		conn, err := d.DialContext(ctx, "udp", "1.1.1.1:443")
		if err == nil && conn != nil {
			_, _ = conn.Write([]byte{0x00})
			_ = conn.Close()
		}
	}()
}
