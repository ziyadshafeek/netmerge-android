package core

import (
	"math"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Family selects which address of a network a flow is pinned to. Load,
// weight and health are tracked per family because one link can behave very
// differently over each (e.g. a carrier NAT that is fast over native IPv6
// and slow over translated IPv4).
type Family int

const (
	Fam4 Family = iota
	Fam6
)

// linkState is the result of the internet probe: fresh networks are
// "unknown" (still preferred over dead ones, so a probe that can't run
// never causes an outage) until the first probe lands.
type linkState int

const (
	stateUnknown linkState = iota
	stateUp
	stateDown
)

func (l linkState) String() string {
	return [...]string{"checking", "up", "down"}[l]
}

// NetworkInfo describes one physical network, as delivered by Kotlin via
// UpdateNetworks. ID is the stable key; Name is the interface name
// (e.g. "wlan0") used for manual weight overrides.
type NetworkInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Transport   string   `json:"transport"`
	IfIndex     int      `json:"ifindex"`
	IPv4        string   `json:"ipv4"`
	IPv6        string   `json:"ipv6"`
	DNS         []string `json:"dns"`
}

// Slot is a network plus its live counters. Counters are atomic so the data
// path never takes the scheduler lock; only new flows (Acquire) and the
// 1-second ticker do.
type Slot struct {
	ID          string
	Name        string
	DisplayName string
	Transport   string
	IfIndex     int
	DNS         []net.IP

	ip4 atomic.Pointer[net.IP]
	ip6 atomic.Pointer[net.IP]

	active, total, failed atomic.Int64 // active is across families
	actF                  [2]atomic.Int64
	bytesIn, bytesOut     [2]atomic.Int64
	probing               [2]atomic.Bool

	// guarded by Scheduler.mu
	weight    [2]float64
	present   bool
	state     [2]linkState
	lastProbe [2]time.Time
	downUntil [2]time.Time

	lastIn, lastOut [2]int64
	rateIn, rateOut [2]float64 // bytes/s over the last tick
	peak            [2]float64 // observed capacity: max recent rateIn+rateOut
}

func (sl *Slot) ip(f Family) net.IP {
	if f == Fam6 {
		if p := sl.ip6.Load(); p != nil {
			return *p
		}
		return nil
	}
	if p := sl.ip4.Load(); p != nil {
		return *p
	}
	return nil
}

// canCarry reports whether this slot can carry flows of family f.
// An IPv6-only cellular network (Jio) can still carry IPv4 (Fam4) flows
// via Android's 464XLAT (bound via Network.bindSocket) or our RFC 6052
// NAT64 synthesis in egress.go.
func (sl *Slot) canCarry(f Family) bool {
	if sl.ip(f) != nil {
		return true
	}
	if f == Fam4 && sl.Transport == "CELLULAR" && sl.ip(Fam6) != nil {
		return true
	}
	return false
}

// effectiveFamily returns the family whose probe state/weight should be
// consulted for flows of family f. For IPv6-only cellular carrying IPv4
// via NAT64/CLAT, the Fam6 state applies.
func (sl *Slot) effectiveFamily(f Family) Family {
	if sl.ip(f) == nil && f == Fam4 && sl.Transport == "CELLULAR" && sl.ip(Fam6) != nil {
		return Fam6
	}
	return f
}

// Scheduler is weighted least-active-flows, per address family: each new
// flow goes to the network with the lowest (active+1)/weight among the
// eligible ones. Only new flows take the lock.
type Scheduler struct {
	mu     sync.Mutex
	slots  []*Slot
	auto   bool // derive weights from observed throughput
	manual map[string]float64
	now    func() time.Time
}

func newScheduler(manual map[string]float64) *Scheduler {
	return &Scheduler{
		auto:   len(manual) == 0,
		manual: manual,
		now:    time.Now,
	}
}

func parseIP(s string) net.IP {
	// Strip %interface zone ID: Android's Inet6Address.getHostAddress()
	// appends e.g. "%rmnet_data0", and net.ParseIP returns nil for those.
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip
}

// manualWeight returns the configured weight for a network, matching by
// interface name first, then by ID. Zero means "not configured".
func (s *Scheduler) manualWeight(id, name string) float64 {
	if w, ok := s.manual[name]; ok && w > 0 {
		return w
	}
	if w, ok := s.manual[id]; ok && w > 0 {
		return w
	}
	return 0
}

// Update applies a re-scan from Kotlin: keeps counters of known networks,
// picks up changed addresses (DHCP renewal, new IPv6 prefix), adds new ones
// and drops vanished ones once their last flow ends. Networks are keyed by ID.
func (s *Scheduler) Update(nets []NetworkInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sl := range s.slots {
		sl.present = false
	}
	for _, n := range nets {
		var ip4, ip6 net.IP
		if x := parseIP(n.IPv4); x != nil {
			ip4 = x.To4()
		}
		if x := parseIP(n.IPv6); x != nil && x.To4() == nil {
			ip6 = x
		}
		var dns []net.IP
		for _, d := range n.DNS {
			if ip := parseIP(d); ip != nil {
				dns = append(dns, ip)
			}
		}
		var found *Slot
		for _, sl := range s.slots {
			if sl.ID == n.ID {
				found = sl
				break
			}
		}
		if found == nil {
			sl := &Slot{
				ID: n.ID, Name: n.Name, DisplayName: n.DisplayName,
				Transport: n.Transport, IfIndex: n.IfIndex, DNS: dns,
				present: true,
			}
			if ip4 != nil {
				sl.ip4.Store(&ip4)
			}
			if ip6 != nil {
				sl.ip6.Store(&ip6)
			}
			sl.weight = [2]float64{1, 1}
			if !s.auto {
				if w := s.manualWeight(n.ID, n.Name); w > 0 {
					sl.weight = [2]float64{w, w}
				}
			}
			s.slots = append(s.slots, sl)
			continue
		}
		found.present = true
		found.Name, found.DisplayName, found.Transport = n.Name, n.DisplayName, n.Transport
		found.IfIndex, found.DNS = n.IfIndex, dns
		if !s.auto {
			if w := s.manualWeight(n.ID, n.Name); w > 0 {
				found.weight = [2]float64{w, w}
			} else {
				found.weight = [2]float64{1, 1}
			}
		}
		old4, old6 := found.ip(Fam4), found.ip(Fam6)
		if !ipEqual(old4, ip4) {
			found.state[Fam4] = stateUnknown // new address: re-verify
		}
		if !ipEqual(old6, ip6) {
			found.state[Fam6] = stateUnknown
		}
		if ip4 != nil {
			found.ip4.Store(&ip4)
		} else {
			found.ip4.Store(nil)
		}
		if ip6 != nil {
			found.ip6.Store(&ip6)
		} else {
			found.ip6.Store(nil)
		}
	}
	kept := s.slots[:0]
	for _, sl := range s.slots {
		if sl.present || sl.active.Load() > 0 {
			kept = append(kept, sl)
		}
	}
	s.slots = kept
}

func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

// A network counts as measured once it has carried this much (bytes/s,
// about 0.4 Mbit/s).
const minMeasuredPeak = 50_000

// Tick samples throughput per family once per tick (the engine calls it
// every second). With auto on, a family's weights follow each network's
// observed peak for that family (floored at 0.05, so a slow path still sees
// an occasional flow and is re-measured). Until every network with that
// family has been measured the weights stay equal, which spreads load so
// each one gets measured. The peak holds while a network is idle and only
// decays when it is in use but underperforming, so capacity is remembered
// across pauses.
func (s *Scheduler) Tick(dt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := dt.Seconds()
	if sec <= 0 {
		return
	}
	for _, f := range []Family{Fam4, Fam6} {
		var maxPeak float64
		live, measured := 0, true
		idle := map[*Slot]bool{}
		for _, sl := range s.slots {
			in, out := sl.bytesIn[f].Load(), sl.bytesOut[f].Load()
			sl.rateIn[f] = float64(in-sl.lastIn[f]) / sec
			sl.rateOut[f] = float64(out-sl.lastOut[f]) / sec
			sl.lastIn[f], sl.lastOut[f] = in, out
			r := sl.rateIn[f] + sl.rateOut[f]
			if r >= 0.05*sl.peak[f] {
				sl.peak[f] = math.Max(r, sl.peak[f]*0.97)
			} else {
				idle[sl] = true
			}
			if !sl.present || sl.ip(f) == nil {
				continue
			}
			live++
			maxPeak = math.Max(maxPeak, sl.peak[f])
		}
		// An idle network's old estimate may be stale or pessimistic (it was
		// measured during a bad moment and then starved of flows, so it could
		// never correct itself). Let it drift back up, capped at half of the
		// best network, so it keeps getting a fair chance to be re-measured.
		for sl := range idle {
			if sl.present && sl.ip(f) != nil && sl.peak[f] > 0 {
				sl.peak[f] = math.Min(sl.peak[f]*1.03, math.Max(sl.peak[f], 0.5*maxPeak))
			}
		}
		for _, sl := range s.slots {
			if sl.present && sl.ip(f) != nil && sl.peak[f] < minMeasuredPeak {
				measured = false
			}
		}
		if !s.auto {
			continue
		}
		for _, sl := range s.slots {
			if !sl.present || sl.ip(f) == nil {
				continue
			}
			if live < 2 || !measured {
				sl.weight[f] = 1
			} else {
				sl.weight[f] = math.Max(0.05, sl.peak[f]/maxPeak)
			}
		}
	}
}

// AcquireFor picks a network that has an address of the given family,
// skipping the ones in skip. The caller must Release it (via ReleaseFor).
func (s *Scheduler) AcquireFor(f Family, skip map[string]struct{}) *Slot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Tiers: 0 = probed up, 1 = not probed yet, 2 = probe failed or link
	// error cooldown. Only the best non-empty tier is used, so a dead link
	// gets no flows but, if every network looks dead, flows still go
	// somewhere rather than nowhere.
	var tiers [3][]*Slot
	for _, sl := range s.slots {
		if !sl.present || !sl.canCarry(f) {
			continue
		}
		if _, no := skip[sl.ID]; no {
			continue
		}
		// For IPv6-only cellular carrying IPv4 via NAT64/CLAT, use the
		// Fam6 probe state — that's the family that was actually probed.
		ef := sl.effectiveFamily(f)
		t := 1
		switch {
		case now.Before(sl.downUntil[ef]) || sl.state[ef] == stateDown:
			t = 2
		case sl.state[ef] == stateUp:
			t = 0
		}
		tiers[t] = append(tiers[t], sl)
	}
	var pool []*Slot
	for _, tier := range tiers {
		if len(tier) > 0 {
			pool = tier
			break
		}
	}
	if len(pool) == 0 {
		return nil
	}
	// Random start so ties don't resonate with the arrival pattern (a
	// rotating counter can lock onto e.g. "every third flow is a short
	// DNS-like one" and starve a network).
	start := rand.IntN(len(pool))
	var best *Slot
	bestScore := math.Inf(1)
	for i := range pool {
		sl := pool[(start+i)%len(pool)]
		if score := float64(sl.actF[f].Load()+1) / sl.weight[f]; score < bestScore {
			best, bestScore = sl, score
		}
	}
	best.active.Add(1)
	best.actF[f].Add(1)
	best.total.Add(1)
	return best
}

// ReleaseFor returns a flow acquired with AcquireFor.
func (s *Scheduler) ReleaseFor(sl *Slot, f Family) {
	if sl == nil {
		return
	}
	sl.active.Add(-1)
	sl.actF[f].Add(-1)
}

// SetState records a probe result. A passing probe also clears any
// link-error cooldown.
func (s *Scheduler) SetState(sl *Slot, f Family, up bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up {
		sl.state[f] = stateUp
		sl.downUntil[f] = time.Time{}
	} else {
		sl.state[f] = stateDown
	}
}

// Fail sidelines a network whose link itself is broken (for one address
// family) for the cooldown duration.
func (s *Scheduler) Fail(sl *Slot, f Family, cooldown time.Duration) {
	s.mu.Lock()
	sl.downUntil[f] = s.now().Add(cooldown)
	s.mu.Unlock()
	sl.failed.Add(1)
}

// V6Usable reports whether any network can currently carry IPv6.
func (s *Scheduler) V6Usable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sl := range s.slots {
		if sl.present && sl.ip(Fam6) != nil && sl.state[Fam6] != stateDown {
			return true
		}
	}
	return false
}

// snapshot returns a copy of the slots for stats/probing. The Slot pointers
// stay valid (counters are atomic).
func (s *Scheduler) snapshot() []*Slot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Slot, len(s.slots))
	copy(out, s.slots)
	return out
}
