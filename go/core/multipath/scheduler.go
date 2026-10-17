package multipath

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type LinkStats struct {
	Link          LinkType
	SRTT          time.Duration
	RTTVar        time.Duration
	MinRTT        time.Duration
	PeakBps       float64
	SmoothedBps   float64
	ActiveFlows   int64
	TotalBytes    int64
	ConsecFails   uint32
	Healthy       bool
	LastUpdatedAt time.Time
}

type linkTracker struct {
	mu            sync.RWMutex
	link          LinkType
	srttNs        int64
	rttVarNs      int64
	minRttNs      int64
	smoothedBps   float64
	peakBps       float64
	deficitCredit float64
	windowBytes   int64
	windowStart   time.Time
	lastUpdated   time.Time
	activeFlows   atomic.Int64
	totalBytes    atomic.Int64
	consecFails   atomic.Uint32
}

type Scheduler struct {
	wifi      *linkTracker
	cellular  *linkTracker
	dispatchN atomic.Uint64
}

func NewScheduler() *Scheduler {
	now := time.Now()
	return &Scheduler{
		wifi: &linkTracker{
			link:        LinkWiFi,
			srttNs:      int64(18 * time.Millisecond),
			minRttNs:    int64(10 * time.Millisecond),
			smoothedBps: 4 * 1024 * 1024, // 32 Mbps initial prior
			windowStart: now,
			lastUpdated: now,
		},
		cellular: &linkTracker{
			link:        LinkCellular,
			srttNs:      int64(32 * time.Millisecond),
			minRttNs:    int64(20 * time.Millisecond),
			smoothedBps: 6 * 1024 * 1024, // 48 Mbps initial 5G prior so 5G is probed immediately
			windowStart: now,
			lastUpdated: now,
		},
	}
}

func (s *Scheduler) tracker(link LinkType) *linkTracker {
	if link == LinkCellular {
		return s.cellular
	}
	return s.wifi
}

// RecordRTT updates Jacobson/Karels SRTT and minimum RTT estimates per physical link.
func (s *Scheduler) RecordRTT(link LinkType, rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	t := s.tracker(link)
	ns := int64(rtt)

	t.mu.Lock()
	if t.srttNs == 0 {
		t.srttNs = ns
		t.rttVarNs = ns / 2
		t.minRttNs = ns
	} else {
		diff := t.srttNs - ns
		if diff < 0 {
			diff = -diff
		}
		t.rttVarNs = (3*t.rttVarNs + diff) / 4
		t.srttNs = (7*t.srttNs + ns) / 8
		if ns < t.minRttNs || time.Since(t.lastUpdated) > 30*time.Second {
			t.minRttNs = ns
		}
	}
	t.lastUpdated = time.Now()
	t.mu.Unlock()
	t.consecFails.Store(0)
}

// RecordBytes updates real-time sliding-window goodput and peak capacity per link.
func (s *Scheduler) RecordBytes(link LinkType, n int64, elapsed time.Duration) {
	if n <= 0 {
		return
	}
	t := s.tracker(link)
	t.totalBytes.Add(n)
	t.consecFails.Store(0)

	now := time.Now()
	t.mu.Lock()
	t.windowBytes += n
	winDur := now.Sub(t.windowStart)
	if winDur >= 120*time.Millisecond {
		instBps := float64(t.windowBytes) / winDur.Seconds()
		if instBps > t.smoothedBps {
			// Fast attack when link ramps up (critical for 5G NR carrier aggregation).
			t.smoothedBps = 0.45*t.smoothedBps + 0.55*instBps
		} else {
			// Slow decay during brief burst pauses so capacity estimate remains stable.
			t.smoothedBps = 0.85*t.smoothedBps + 0.15*instBps
		}
		if instBps > t.peakBps {
			t.peakBps = instBps
		} else {
			t.peakBps *= 0.995
		}
		t.windowBytes = 0
		t.windowStart = now
		t.lastUpdated = now
	}
	t.mu.Unlock()
}

func (s *Scheduler) RecordSuccess(link LinkType) {
	s.tracker(link).consecFails.Store(0)
}

func (s *Scheduler) RecordFailure(link LinkType) {
	t := s.tracker(link)
	fails := t.consecFails.Add(1)
	t.mu.Lock()
	if fails >= 2 {
		t.smoothedBps *= 0.5
		if t.smoothedBps < 128*1024 {
			t.smoothedBps = 128 * 1024
		}
	}
	t.mu.Unlock()
}

func (s *Scheduler) AcquireFlow(link LinkType) {
	s.tracker(link).activeFlows.Add(1)
}

func (s *Scheduler) ReleaseFlow(link LinkType) {
	t := s.tracker(link)
	for {
		cur := t.activeFlows.Load()
		if cur <= 0 {
			return
		}
		if t.activeFlows.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

func (s *Scheduler) Stats(link LinkType) LinkStats {
	t := s.tracker(link)
	t.mu.RLock()
	srtt := time.Duration(t.srttNs)
	rttVar := time.Duration(t.rttVarNs)
	minRTT := time.Duration(t.minRttNs)
	smoothed := t.smoothedBps
	peak := t.peakBps
	updated := t.lastUpdated
	t.mu.RUnlock()

	fails := t.consecFails.Load()
	return LinkStats{
		Link:          link,
		SRTT:          srtt,
		RTTVar:        rttVar,
		MinRTT:        minRTT,
		PeakBps:       peak,
		SmoothedBps:   smoothed,
		ActiveFlows:   t.activeFlows.Load(),
		TotalBytes:    t.totalBytes.Load(),
		ConsecFails:   fails,
		Healthy:       fails < 4,
		LastUpdatedAt: updated,
	}
}

// EstimatedCompletionTime calculates the expected time in seconds to transfer
// payloadBytes over the target link, accounting for queuing delay, active flow
// contention, and 5G NR RLC/PDCP bufferbloat inflation.
func (s *Scheduler) EstimatedCompletionTime(link LinkType, payloadBytes int64) float64 {
	if payloadBytes <= 0 {
		payloadBytes = 64 * 1024
	}
	t := s.tracker(link)
	t.mu.RLock()
	srttSec := float64(t.srttNs) / 1e9
	minRttSec := float64(t.minRttNs) / 1e9
	bps := t.smoothedBps
	peak := t.peakBps
	t.mu.RUnlock()

	if srttSec <= 0 {
		srttSec = 0.025
	}
	if minRttSec <= 0 || minRttSec > srttSec {
		minRttSec = srttSec
	}
	if peak > bps {
		// Blend smoothed rate with 35% of observed peak so bursty 5G channels
		// aren't undervalued between active windows.
		bps = 0.65*bps + 0.35*peak
	}
	if bps < 128*1024 {
		bps = 128 * 1024
	}

	active := float64(t.activeFlows.Load())
	effectiveBps := bps / (1.0 + 0.35*active)

	// Bufferbloat penalty: if standing queue inflates SRTT far above MinRTT,
	// penalize new flow assignment proportionally.
	bloatRatio := srttSec / minRttSec
	if bloatRatio > 2.5 {
		bloatRatio = 2.5
	}

	transferSec := float64(payloadBytes) / effectiveBps
	penalty := 1.0 + 0.6*float64(t.consecFails.Load())
	return (srttSec*bloatRatio + transferSec) * penalty
}

// SelectLinks chooses the primary and secondary physical links for a new flow
// using Deficit Inverse-Completion-Time water-filling and computes the optimal
// head-start stagger before launching the secondary racer socket.
func (s *Scheduler) SelectLinks(expectedBytes int64) (primary LinkType, secondary LinkType, stagger time.Duration) {
	seq := s.dispatchN.Add(1)

	wStats := s.Stats(LinkWiFi)
	cStats := s.Stats(LinkCellular)

	// If one link is unhealthy, immediately promote the healthy survivor.
	if !wStats.Healthy && cStats.Healthy {
		return LinkCellular, LinkWiFi, 180 * time.Millisecond
	}
	if !cStats.Healthy && wStats.Healthy {
		return LinkWiFi, LinkCellular, 180 * time.Millisecond
	}

	// Active Dual-Path Probing: every 4th flow or when Cellular has 0 active flows
	// while Wi-Fi is busy, force a probe on Jio 5G so 5G NR RRC stays in
	// RRC_CONNECTED with MIMO carrier aggregation awake.
	if (seq%4 == 0) || (cStats.ActiveFlows == 0 && wStats.ActiveFlows >= 1) {
		return LinkCellular, LinkWiFi, 20 * time.Millisecond
	}
	if wStats.ActiveFlows == 0 && cStats.ActiveFlows >= 2 {
		return LinkWiFi, LinkCellular, 20 * time.Millisecond
	}

	ectWiFi := s.EstimatedCompletionTime(LinkWiFi, expectedBytes)
	ectCell := s.EstimatedCompletionTime(LinkCellular, expectedBytes)

	// Inverse completion time weights -> proportional bandwidth water-filling.
	invW := 1.0 / math.Max(ectWiFi, 0.001)
	invC := 1.0 / math.Max(ectCell, 0.001)
	sumInv := invW + invC
	shareW := invW / sumInv
	shareC := invC / sumInv

	s.wifi.mu.Lock()
	s.wifi.deficitCredit += shareW
	wCredit := s.wifi.deficitCredit
	s.wifi.mu.Unlock()

	s.cellular.mu.Lock()
	s.cellular.deficitCredit += shareC
	cCredit := s.cellular.deficitCredit
	s.cellular.mu.Unlock()

	if cCredit >= wCredit {
		s.cellular.mu.Lock()
		s.cellular.deficitCredit -= 1.0
		s.cellular.mu.Unlock()
		primary, secondary = LinkCellular, LinkWiFi
	} else {
		s.wifi.mu.Lock()
		s.wifi.deficitCredit -= 1.0
		s.wifi.mu.Unlock()
		primary, secondary = LinkWiFi, LinkCellular
	}

	// Dynamic head-start: tight stagger (15-45 ms) so both links race closely
	// without wasting sockets when the primary connects instantaneously.
	pStats := s.Stats(primary)
	stagger = pStats.SRTT/2 + pStats.RTTVar
	if stagger < 15*time.Millisecond {
		stagger = 15 * time.Millisecond
	} else if stagger > 45*time.Millisecond {
		stagger = 45 * time.Millisecond
	}
	return primary, secondary, stagger
}

// SplitBytes divides a byte range across Wi-Fi and Cellular proportional to their
// real-time BDP and goodput so parallel HTTP Range requests finish simultaneously.
func (s *Scheduler) SplitBytes(totalBytes int64) (wifiBytes int64, cellBytes int64) {
	if totalBytes <= 0 {
		return 0, 0
	}
	wStats := s.Stats(LinkWiFi)
	cStats := s.Stats(LinkCellular)

	wRate := math.Max(wStats.SmoothedBps, 256*1024)
	cRate := math.Max(cStats.SmoothedBps, 256*1024)

	if !wStats.Healthy && cStats.Healthy {
		return 0, totalBytes
	}
	if !cStats.Healthy && wStats.Healthy {
		return totalBytes, 0
	}

	cellRatio := cRate / (wRate + cRate)
	if cellRatio < 0.20 {
		cellRatio = 0.20
	} else if cellRatio > 0.85 {
		cellRatio = 0.85
	}

	cellBytes = int64(float64(totalBytes) * cellRatio)
	// Align split boundary to 4 KB pages.
	const align = 4096
	if cellBytes > align {
		cellBytes = (cellBytes / align) * align
	}
	wifiBytes = totalBytes - cellBytes
	return wifiBytes, cellBytes
}
