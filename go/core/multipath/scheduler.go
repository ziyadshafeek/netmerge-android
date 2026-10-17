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
	lastFailAt    time.Time
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
			rttVarNs:    int64(6 * time.Millisecond),
			minRttNs:    int64(10 * time.Millisecond),
			smoothedBps: 5 * 1024 * 1024, // 40 Mbps initial prior
			windowStart: now,
			lastUpdated: now,
		},
		cellular: &linkTracker{
			link:        LinkCellular,
			srttNs:      int64(38 * time.Millisecond),
			rttVarNs:    int64(14 * time.Millisecond),
			minRttNs:    int64(22 * time.Millisecond),
			smoothedBps: 7 * 1024 * 1024, // 56 Mbps initial 5G prior
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
	if winDur >= 100*time.Millisecond {
		instBps := float64(t.windowBytes) / winDur.Seconds()
		if instBps > t.smoothedBps {
			t.smoothedBps = 0.40*t.smoothedBps + 0.60*instBps
		} else {
			t.smoothedBps = 0.88*t.smoothedBps + 0.12*instBps
		}
		if instBps > t.peakBps {
			t.peakBps = instBps
		} else {
			t.peakBps *= 0.996
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
	t.lastFailAt = time.Now()
	if fails >= 3 {
		t.smoothedBps *= 0.65
		if t.smoothedBps < 512*1024 {
			t.smoothedBps = 512 * 1024
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
	lastFail := t.lastFailAt
	t.mu.RUnlock()

	fails := t.consecFails.Load()
	// Auto-heal consecutive failures after 4 seconds so a transient 5G handover
	// never permanently marks Cellular unhealthy.
	if fails >= 5 && !lastFail.IsZero() && time.Since(lastFail) > 4*time.Second {
		t.consecFails.Store(2)
		fails = 2
	}

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
		Healthy:       fails < 5,
		LastUpdatedAt: updated,
	}
}

func (s *Scheduler) EstimatedCompletionTime(link LinkType, payloadBytes int64) float64 {
	if payloadBytes <= 0 {
		payloadBytes = 128 * 1024
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
		bps = 0.55*bps + 0.45*peak
	}
	if bps < 512*1024 {
		bps = 512 * 1024
	}

	active := float64(t.activeFlows.Load())
	// Penalize links with many active flows so new flows spill over onto the second link.
	effectiveBps := bps / (1.0 + 0.55*active)

	bloatRatio := srttSec / minRttSec
	if bloatRatio > 2.2 {
		bloatRatio = 2.2
	}

	transferSec := float64(payloadBytes) / effectiveBps
	penalty := 1.0 + 0.35*float64(t.consecFails.Load())
	return (srttSec*bloatRatio + transferSec) * penalty
}

// SelectLinks assigns the primary and secondary links for a new flow and returns
// a realistic failover delay (`stagger`) that allows the assigned link (especially
// 5G NR) to complete its TCP handshake without being hijacked by Wi-Fi's shorter RTT.
func (s *Scheduler) SelectLinks(expectedBytes int64) (primary LinkType, secondary LinkType, stagger time.Duration) {
	seq := s.dispatchN.Add(1)

	wStats := s.Stats(LinkWiFi)
	cStats := s.Stats(LinkCellular)

	if !wStats.Healthy && cStats.Healthy {
		return LinkCellular, LinkWiFi, 350 * time.Millisecond
	}
	if !cStats.Healthy && wStats.Healthy {
		return LinkWiFi, LinkCellular, 250 * time.Millisecond
	}

	// Calculate target bandwidth share with a guaranteed minimum 40% floor for Cellular
	// so both radios always stay saturated in parallel.
	wCap := math.Max(wStats.SmoothedBps, 0.6*wStats.PeakBps)
	cCap := math.Max(cStats.SmoothedBps, 0.6*cStats.PeakBps)
	if wCap < 512*1024 {
		wCap = 512 * 1024
	}
	if cCap < 512*1024 {
		cCap = 512 * 1024
	}
	targetCellShare := cCap / (wCap + cCap)
	if targetCellShare < 0.40 {
		targetCellShare = 0.40
	} else if targetCellShare > 0.75 {
		targetCellShare = 0.75
	}
	targetWiFiShare := 1.0 - targetCellShare

	// 1. Idle-Link Wakeup First: NEVER let either radio sit at 0 flows when the other is busy.
	totalFlows := wStats.ActiveFlows + cStats.ActiveFlows
	actualCellShare := 0.5
	if totalFlows > 0 {
		actualCellShare = float64(cStats.ActiveFlows) / float64(totalFlows)
	}

	if wStats.ActiveFlows == 0 && cStats.ActiveFlows >= 1 {
		// Wi-Fi is idle while Cellular is active -> force this flow onto Wi-Fi!
		primary, secondary = LinkWiFi, LinkCellular
	} else if cStats.ActiveFlows == 0 && wStats.ActiveFlows >= 1 {
		// Cellular is idle while Wi-Fi is active -> force this flow onto Cellular!
		primary, secondary = LinkCellular, LinkWiFi
	} else if totalFlows == 0 {
		// First flow from idle: alternate cleanly so sequential probes wake both links,
		// favoring whichever link currently has higher measured goodput.
		if seq%2 == 1 && wCap >= cCap {
			primary, secondary = LinkWiFi, LinkCellular
		} else if seq%2 == 0 {
			primary, secondary = LinkWiFi, LinkCellular
		} else {
			primary, secondary = LinkCellular, LinkWiFi
		}
	} else if actualCellShare < targetCellShare {
		primary, secondary = LinkCellular, LinkWiFi
	} else if (1.0 - actualCellShare) < targetWiFiShare {
		primary, secondary = LinkWiFi, LinkCellular
	} else {
		// 2. Bounded Deficit Inverse-Completion-Time Water-Filling.
		ectWiFi := s.EstimatedCompletionTime(LinkWiFi, expectedBytes)
		ectCell := s.EstimatedCompletionTime(LinkCellular, expectedBytes)

		invW := (1.0 / math.Max(ectWiFi, 0.001)) * targetWiFiShare
		invC := (1.0 / math.Max(ectCell, 0.001)) * targetCellShare
		sumInv := invW + invC
		shareW := invW / sumInv
		shareC := invC / sumInv

		s.wifi.mu.Lock()
		s.wifi.deficitCredit = clampFloat(s.wifi.deficitCredit+shareW, -1.5, 1.5)
		wCredit := s.wifi.deficitCredit
		s.wifi.mu.Unlock()

		s.cellular.mu.Lock()
		s.cellular.deficitCredit = clampFloat(s.cellular.deficitCredit+shareC, -1.5, 1.5)
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
	}

	// Compute failover delay (`stagger`) for the chosen primary link.
	// CRITICAL FIX: Cellular requires 260-340 ms before launching Wi-Fi failover
	// so Wi-Fi never steals Cellular's assigned connections during 5G NR handshakes.
	pStats := s.Stats(primary)
	stagger = pStats.SRTT + 3*pStats.RTTVar
	if primary == LinkCellular {
		minCellStagger := 260 * time.Millisecond
		if cStats.ActiveFlows == 0 {
			minCellStagger = 340 * time.Millisecond // Allow 5G RRC_INACTIVE -> RRC_CONNECTED wakeup
		}
		if stagger < minCellStagger {
			stagger = minCellStagger
		} else if stagger > 450*time.Millisecond {
			stagger = 450 * time.Millisecond
		}
	} else {
		if stagger < 140*time.Millisecond {
			stagger = 140 * time.Millisecond
		} else if stagger > 280*time.Millisecond {
			stagger = 280 * time.Millisecond
		}
	}
	return primary, secondary, stagger
}

func (s *Scheduler) SplitBytes(totalBytes int64) (wifiBytes int64, cellBytes int64) {
	if totalBytes <= 0 {
		return 0, 0
	}
	wStats := s.Stats(LinkWiFi)
	cStats := s.Stats(LinkCellular)

	wRate := math.Max(wStats.SmoothedBps, 0.5*wStats.PeakBps)
	cRate := math.Max(cStats.SmoothedBps, 0.5*cStats.PeakBps)
	wRate = math.Max(wRate, 512*1024)
	cRate = math.Max(cRate, 512*1024)

	if !wStats.Healthy && cStats.Healthy {
		return 0, totalBytes
	}
	if !cStats.Healthy && wStats.Healthy {
		return totalBytes, 0
	}

	cellRatio := cRate / (wRate + cRate)
	if cellRatio < 0.35 {
		cellRatio = 0.35
	} else if cellRatio > 0.75 {
		cellRatio = 0.75
	}

	cellBytes = int64(float64(totalBytes) * cellRatio)
	const align = 4096
	if cellBytes > align {
		cellBytes = (cellBytes / align) * align
	}
	wifiBytes = totalBytes - cellBytes
	return wifiBytes, cellBytes
}

func clampFloat(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}
