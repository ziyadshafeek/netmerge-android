// Package multipath implements the NetMerge multipath data-plane helpers:
// link-quality tracking, socket binding, DNS resolution and L7 splicing
// across Wi-Fi and cellular links.
package multipath

import (
	"sync"
	"sync/atomic"
	"time"
)

// LinkType, LinkWiFi, LinkCellular are defined in binder.go.

// LinkMetrics tracks real-time quality signals for one link: an EWMA of
// observed round-trip time and of observed goodput (bytes/sec), plus the
// number of bytes currently assigned to the link but not yet delivered.
type LinkMetrics struct {
	mu          sync.RWMutex
	ewmaRTT     float64 // seconds
	ewmaGoodput float64 // bytes per second
	inFlight    atomic.Int64
}

// ECTScheduler picks, for each new unit of work, the link that is expected
// to finish delivering it first (minimum Estimated Completion Time),
// instead of blind round-robin.
type ECTScheduler struct {
	WiFi *LinkMetrics
	Cell *LinkMetrics
}

// NewECTScheduler returns an ECTScheduler with sane seeds so the first
// decisions are reasonable before any measurements exist: Wi-Fi is assumed
// lower-latency (15ms) than cellular (45ms), both at 5 MB/s.
func NewECTScheduler() *ECTScheduler {
	return &ECTScheduler{
		WiFi: &LinkMetrics{ewmaRTT: 0.015, ewmaGoodput: 5 * 1024 * 1024},
		Cell: &LinkMetrics{ewmaRTT: 0.045, ewmaGoodput: 5 * 1024 * 1024},
	}
}

// RecordRTT folds one round-trip sample into the EWMA (alpha 0.2).
// Non-positive samples are ignored.
func (m *LinkMetrics) RecordRTT(rtt time.Duration) {
	sample := rtt.Seconds()
	if sample <= 0 {
		return
	}
	m.mu.Lock()
	m.ewmaRTT = 0.8*m.ewmaRTT + 0.2*sample
	m.mu.Unlock()
}

// RecordTransfer folds one completed transfer into the goodput EWMA
// (alpha 0.25). Transfers smaller than 16KB are ignored: their timing is
// dominated by handshake overhead, not link throughput.
func (m *LinkMetrics) RecordTransfer(bytes int64, duration time.Duration) {
	if bytes < 16*1024 || duration <= 0 {
		return
	}
	rate := float64(bytes) / duration.Seconds()
	m.mu.Lock()
	m.ewmaGoodput = 0.75*m.ewmaGoodput + 0.25*rate
	m.mu.Unlock()
}

// AddInFlight adds n (negative to release) to the in-flight byte counter.
func (m *LinkMetrics) AddInFlight(n int64) {
	m.inFlight.Add(n)
}

// InFlight returns the current in-flight byte count.
func (m *LinkMetrics) InFlight() int64 {
	return m.inFlight.Load()
}

// EstimateCompletionTime returns the expected seconds until expectedBytes
// more bytes finish on this link: one RTT plus the backlog (already
// in-flight bytes plus the new bytes) drained at the measured goodput.
// Goodput is floored at 64KB/s so a stalled link degrades gracefully
// instead of dividing by ~zero.
func (m *LinkMetrics) EstimateCompletionTime(expectedBytes int64) float64 {
	m.mu.RLock()
	rtt := m.ewmaRTT
	bw := m.ewmaGoodput
	m.mu.RUnlock()

	if bw < 64*1024 {
		bw = 64 * 1024
	}
	backlog := float64(m.inFlight.Load() + expectedBytes)
	return rtt + (backlog / bw)
}

// PickOptimalLink returns the link with the lower estimated completion
// time for expectedBytes. Ties go to Wi-Fi.
func (s *ECTScheduler) PickOptimalLink(expectedBytes int64) LinkType {
	if s.Cell.EstimateCompletionTime(expectedBytes) < s.WiFi.EstimateCompletionTime(expectedBytes) {
		return LinkCellular
	}
	return LinkWiFi
}
