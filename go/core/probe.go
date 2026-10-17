package core

import (
	"time"
)

// Internet reachability probes: a TCP connect to well-known anycast IPs,
// bound to the network's interface and protected from the VPN (same
// egressControl as real flows, so the probe tests the real path).
var (
	probeTargets4 = []string{"1.1.1.1:443", "8.8.8.8:443"}
	probeTargets6 = []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"}
)

const (
	probeTimeout   = 2 * time.Second
	probeEveryUp   = 15 * time.Second
	probeEveryDown = 4 * time.Second
)

type probeJob struct {
	sl *Slot
	f  Family
}

// probeDue returns the (slot, family) pairs that need a probe now and marks
// them in flight. New/unknown networks probe immediately, healthy ones every
// 15s, dead ones every 4s so they rejoin quickly. Called from the single
// 1-second engine tick: battery-sane.
func (e *Engine) probeDue() []probeJob {
	s := e.scheduler
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var due []probeJob
	for _, sl := range s.slots {
		if !sl.present {
			continue
		}
		for _, f := range []Family{Fam4, Fam6} {
			if sl.ip(f) == nil || sl.probing[f].Load() {
				continue
			}
			every := probeEveryUp
			switch sl.state[f] {
			case stateUnknown:
				every = 0 // probe immediately
			case stateDown:
				every = probeEveryDown
			}
			if now.Sub(sl.lastProbe[f]) >= every {
				sl.lastProbe[f] = now
				sl.probing[f].Store(true)
				due = append(due, probeJob{sl, f})
			}
		}
	}
	return due
}

// runProbe dials the probe targets through the slot's interface. Either
// target answering means the link has internet.
func (e *Engine) runProbe(sl *Slot, f Family) {
	defer func() { _ = recover() }()
	defer sl.probing[f].Store(false)

	targets := probeTargets4
	if f == Fam6 {
		targets = probeTargets6
	}
	ok := false
	for _, t := range targets {
		host, port := splitHostPort(t)
		c, err := e.dialBound(sl, f, "tcp", host, port, probeTimeout)
		if err == nil {
			c.Close()
			ok = true
			break
		}
	}
	e.scheduler.SetState(sl, f, ok)
}

func splitHostPort(hp string) (string, int) {
	// targets are constants; keep it simple and panic-free.
	for i := len(hp) - 1; i >= 0; i-- {
		if hp[i] == ':' {
			port := 0
			for _, c := range hp[i+1:] {
				port = port*10 + int(c-'0')
			}
			return hp[:i], port
		}
	}
	return hp, 443
}
