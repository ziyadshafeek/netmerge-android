package core

import (
	"encoding/json"
)

// statsJSON builds the GetStats payload. Counters are atomic; the slot list
// is snapshotted under the scheduler lock.
func (e *Engine) statsJSON() string {
	type netStat struct {
		ID          string  `json:"id"`
		DisplayName string  `json:"displayName"`
		Transport   string  `json:"transport"`
		State       string  `json:"state"`
		TxBytes     int64   `json:"txBytes"`
		RxBytes     int64   `json:"rxBytes"`
		ActiveFlows int64   `json:"activeFlows"`
		Weight      float64 `json:"weight"`
	}
	type totals struct {
		TxBytes     int64 `json:"txBytes"`
		RxBytes     int64 `json:"rxBytes"`
		ActiveFlows int64 `json:"activeFlows"`
	}
	type payload struct {
		Running  bool      `json:"running"`
		Networks []netStat `json:"networks"`
		Totals   totals    `json:"totals"`
	}

	p := payload{Running: true, Networks: []netStat{}}
	for _, sl := range e.scheduler.snapshot() {
		// tx = bytes we sent upstream (upload), rx = bytes we got back.
		tx := sl.bytesOut[Fam4].Load() + sl.bytesOut[Fam6].Load()
		rx := sl.bytesIn[Fam4].Load() + sl.bytesIn[Fam6].Load()
		ns := netStat{
			ID: sl.ID, DisplayName: sl.DisplayName, Transport: sl.Transport,
			State: combinedState(sl).String(),
			TxBytes: tx, RxBytes: rx,
			ActiveFlows: sl.active.Load(),
			Weight:      round2(combinedWeight(sl)),
		}
		p.Networks = append(p.Networks, ns)
		p.Totals.TxBytes += tx
		p.Totals.RxBytes += rx
		p.Totals.ActiveFlows += sl.active.Load()
	}
	b, _ := json.Marshal(p)
	return string(b)
}

// combinedState reports the link's overall health across address families.
// A family without an address is not probeable and doesn't count: on
// IPv6-only carriers (e.g. Jio) the IPv4 state would otherwise sit at
// "checking" forever and mask a perfectly healthy IPv6 path.
func combinedState(sl *Slot) linkState {
	anyProbed, anyUnknown := false, false
	for _, f := range []Family{Fam4, Fam6} {
		if sl.ip(f) == nil {
			continue
		}
		anyProbed = true
		switch sl.state[f] {
		case stateUp:
			return stateUp
		case stateUnknown:
			anyUnknown = true
		}
	}
	if !anyProbed {
		return stateUnknown
	}
	if anyUnknown {
		return stateUnknown
	}
	return stateDown
}

// combinedWeight mirrors combinedState: prefer the weight of a family that
// is up, otherwise the best known weight.
func combinedWeight(sl *Slot) float64 {
	best := 0.0
	for _, f := range []Family{Fam4, Fam6} {
		if sl.ip(f) == nil {
			continue
		}
		if sl.state[f] == stateUp {
			return sl.weight[f]
		}
		if sl.weight[f] > best {
			best = sl.weight[f]
		}
	}
	if best == 0 {
		return 1.0
	}
	return best
}

// round2 keeps weights readable in the UI.
func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
