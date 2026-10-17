// Package multipath implements the zero-VPS compounding engine for NetMerge
// Android: dual-stack DNS, byte-range splicing, QUIC elephant-flow eviction,
// and ECT-based link scheduling. This file contains the elephant-flow
// QUIC guard.
//
// Rationale: modern apps multiplex dozens of requests into a single UDP/443
// QUIC socket. A QUIC socket is pinned to one network 5-tuple, so a single
// bulk download over QUIC can never use the second radio. Blocking UDP/443
// outright would add handshake latency to every interactive flow (YouTube
// startup, Instagram, API calls). Instead, let all QUIC run natively and
// only evict *elephant* flows: sustained bulk transfers that would benefit
// from being re-done as multi-socket TCP across both links.
package multipath

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ElephantByteThreshold is the total transfer size above which a UDP/443
	// flow is considered a bulk (elephant) flow rather than interactive.
	ElephantByteThreshold int64 = 2560 * 1024 // 2.5 MB

	// ElephantRateThreshold is the minimum sustained transfer rate for
	// eviction: a slow trickle is not worth migrating even if large.
	ElephantRateThreshold float64 = 500 * 1024 // 500 KB/s

	// QUICCooldownTTL is how long an evicted (uid, dstIP, dstPort) stays
	// blocked from QUIC: the app's next attempt goes straight to TCP.
	QUICCooldownTTL = 90 * time.Second

	// minEvictAge avoids evicting on a single burst: the flow must sustain
	// the rate for at least this long before it is considered an elephant.
	minEvictAge = 800 * time.Millisecond

	// staleFlowTTL bounds memory: flows that have seen no accounting for
	// this long are dropped by Cleanup (they are presumably dead).
	staleFlowTTL = 5 * time.Minute
)

// UDPFlowTracker accumulates byte counts for one live UDP/443 flow.
type UDPFlowTracker struct {
	StartTime  time.Time
	LastSeen   time.Time
	TotalBytes atomic.Int64
	Evicted    atomic.Bool
}

// ElephantQUICGuard decides which UDP/443 flows stay on QUIC and which are
// evicted to TCP (via ICMP port-unreachable + a cooldown that forces the
// app's retry onto multi-socket TCP, which the scheduler spreads across
// both links).
type ElephantQUICGuard struct {
	mu        sync.RWMutex
	cooldowns map[string]time.Time // key: "uid:dstIP:dstPort"
	flows     map[string]*UDPFlowTracker
}

// NewElephantQUICGuard returns an empty guard.
func NewElephantQUICGuard() *ElephantQUICGuard {
	return &ElephantQUICGuard{
		cooldowns: make(map[string]time.Time),
		flows:     make(map[string]*UDPFlowTracker),
	}
}

func (g *ElephantQUICGuard) key(uid int, dstIP string, dstPort uint16) string {
	return fmt.Sprintf("%d:%s:%d", uid, dstIP, dstPort)
}

// ShouldBlockNewQUIC is consulted on the first UDP/443 packet of a flow.
// It returns true only when this exact (uid, dstIP, dstPort) was recently
// evicted as an elephant flow and the cooldown has not expired; the caller
// then sends ICMP port-unreachable so the app falls back to TCP.
func (g *ElephantQUICGuard) ShouldBlockNewQUIC(uid int, dstIP string, dstPort uint16) bool {
	if dstPort != 443 {
		return false
	}
	k := g.key(uid, dstIP, dstPort)

	g.mu.RLock()
	expiry, exists := g.cooldowns[k]
	g.mu.RUnlock()

	if !exists {
		return false
	}
	if time.Now().Before(expiry) {
		return true
	}
	// Expired: drop it so the map does not grow; the caller lets the
	// packet through and re-evaluates the flow from scratch.
	g.mu.Lock()
	if exp, ok := g.cooldowns[k]; ok && !time.Now().Before(exp) {
		delete(g.cooldowns, k)
	}
	g.mu.Unlock()
	return false
}

// OnUDPPacket accounts packetBytes on the flow identified by flowID.
// secondaryLinkIdle should be true when the second radio has spare
// capacity (there is no point migrating a flow if nothing is idle).
// It returns true exactly once per elephant flow: the caller must then
// terminate the UDP flow and send ICMP port-unreachable.
func (g *ElephantQUICGuard) OnUDPPacket(flowID string, uid int, dstIP string, dstPort uint16, packetBytes int, secondaryLinkIdle bool) bool {
	if dstPort != 443 {
		return false
	}

	now := time.Now()
	g.mu.RLock()
	tracker, ok := g.flows[flowID]
	g.mu.RUnlock()

	if !ok {
		g.mu.Lock()
		tracker, ok = g.flows[flowID]
		if !ok {
			tracker = &UDPFlowTracker{StartTime: now, LastSeen: now}
			g.flows[flowID] = tracker
		}
		g.mu.Unlock()
	}
	tracker.LastSeen = now

	total := tracker.TotalBytes.Add(int64(packetBytes))
	if total < ElephantByteThreshold || !secondaryLinkIdle {
		return false
	}
	if now.Sub(tracker.StartTime) < minEvictAge {
		return false
	}
	rate := float64(total) / now.Sub(tracker.StartTime).Seconds()
	if rate < ElephantRateThreshold {
		return false
	}
	if !tracker.Evicted.CompareAndSwap(false, true) {
		return false // already evicted by a racing packet
	}
	g.mu.Lock()
	g.cooldowns[g.key(uid, dstIP, dstPort)] = now.Add(QUICCooldownTTL)
	delete(g.flows, flowID)
	g.mu.Unlock()
	return true
}

// Cleanup removes expired cooldowns and stale (long-unseen) flows. Call it
// periodically (e.g. every 30-60s from the engine tick) to bound memory.
func (g *ElephantQUICGuard) Cleanup() {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, exp := range g.cooldowns {
		if !now.Before(exp) {
			delete(g.cooldowns, k)
		}
	}
	for id, t := range g.flows {
		if now.Sub(t.LastSeen) > staleFlowTTL {
			delete(g.flows, id)
		}
	}
}

// FlowCount returns the number of tracked live flows (for tests/stats).
func (g *ElephantQUICGuard) FlowCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.flows)
}

// CooldownCount returns the number of active cooldowns (for tests/stats).
func (g *ElephantQUICGuard) CooldownCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.cooldowns)
}
