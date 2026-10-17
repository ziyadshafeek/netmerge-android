package core

import (
	"testing"
)

func testNets() []NetworkInfo {
	return []NetworkInfo{
		{ID: "101", Name: "wlan0", DisplayName: "Wi-Fi", Transport: "WIFI",
			IfIndex: 12, IPv4: "192.168.1.10", DNS: []string{"192.168.1.1"}},
		{ID: "102", Name: "rmnet0", DisplayName: "Cellular", Transport: "CELLULAR",
			IfIndex: 13, IPv4: "10.0.0.5", DNS: []string{"8.8.8.8"}},
	}
}

func upScheduler(nets []NetworkInfo) *Scheduler {
	s := newScheduler(nil)
	s.Update(nets)
	for _, sl := range s.snapshot() {
		s.SetState(sl, Fam4, true)
	}
	return s
}

// With equal weights and no held flows, 200 picks spread ~evenly.
func TestSchedulerDistributesEvenly(t *testing.T) {
	s := upScheduler(testNets())
	counts := map[string]int{}
	for i := 0; i < 200; i++ {
		sl := s.AcquireFor(Fam4, nil)
		if sl == nil {
			t.Fatal("AcquireFor returned nil")
		}
		counts[sl.ID]++
		s.ReleaseFor(sl, Fam4)
	}
	for id, c := range counts {
		if c < 70 || c > 130 {
			t.Fatalf("network %s got %d/200, want ~100", id, c)
		}
	}
}

// A down network gets nothing while another is up.
func TestSchedulerDownGetsNothing(t *testing.T) {
	s := newScheduler(nil)
	s.Update(testNets())
	sls := s.snapshot()
	s.SetState(sls[0], Fam4, true)
	s.SetState(sls[1], Fam4, false)
	for i := 0; i < 50; i++ {
		sl := s.AcquireFor(Fam4, nil)
		if sl == nil {
			t.Fatal("AcquireFor returned nil")
		}
		if sl.ID != "101" {
			t.Fatalf("down network picked: %s", sl.ID)
		}
		s.ReleaseFor(sl, Fam4)
	}
}

// Unknown (unprobed) is preferred over down.
func TestSchedulerUnknownPreferredOverDown(t *testing.T) {
	s := newScheduler(nil)
	s.Update(testNets())
	sls := s.snapshot()
	s.SetState(sls[0], Fam4, false) // down
	// sls[1] stays unknown
	for i := 0; i < 20; i++ {
		sl := s.AcquireFor(Fam4, nil)
		if sl == nil {
			t.Fatal("AcquireFor returned nil")
		}
		if sl.ID != "102" {
			t.Fatalf("expected unknown network, got %s (state down?)", sl.ID)
		}
		s.ReleaseFor(sl, Fam4)
	}
}

// If everything looks dead, flows still go somewhere rather than nowhere.
func TestSchedulerAllDeadStillPicks(t *testing.T) {
	s := newScheduler(nil)
	s.Update(testNets())
	for _, sl := range s.snapshot() {
		s.SetState(sl, Fam4, false)
	}
	sl := s.AcquireFor(Fam4, nil)
	if sl == nil {
		t.Fatal("all dead: AcquireFor returned nil, want a best-effort pick")
	}
	s.ReleaseFor(sl, Fam4)
}

// Manual weight 3:1 yields ~3:1 distribution over held (concurrent) flows.
func TestSchedulerManualWeightRatio(t *testing.T) {
	s := newScheduler(map[string]float64{"wlan0": 3, "rmnet0": 1})
	s.Update(testNets())
	var held []*Slot
	counts := map[string]int{}
	for i := 0; i < 200; i++ {
		sl := s.AcquireFor(Fam4, nil)
		if sl == nil {
			t.Fatal("AcquireFor returned nil")
		}
		held = append(held, sl)
		counts[sl.ID]++
	}
	for _, sl := range held {
		s.ReleaseFor(sl, Fam4)
	}
	// 150:50 nominal; allow generous slack for the random start.
	if counts["101"] < 120 || counts["101"] > 180 {
		t.Fatalf("weight 3 network got %d/200, want ~150", counts["101"])
	}
	if counts["102"] < 20 || counts["102"] > 80 {
		t.Fatalf("weight 1 network got %d/200, want ~50", counts["102"])
	}
}

// Auto weights: all 1 until every network is measured.
func TestSchedulerWeightsOneUntilMeasured(t *testing.T) {
	s := upScheduler(testNets())
	s.Tick(1e9) // 1s, no traffic
	for _, sl := range s.snapshot() {
		if sl.weight[Fam4] != 1 {
			t.Fatalf("unmeasured weight = %v, want 1", sl.weight[Fam4])
		}
	}
}

// Auto weights follow observed peak throughput per family.
func TestSchedulerWeightFollowsPeak(t *testing.T) {
	s := upScheduler(testNets())
	sls := s.snapshot()
	// Simulate 1 MB/s on wlan0, 250 KB/s on rmnet0.
	sls[0].bytesIn[Fam4].Add(1_000_000)
	sls[1].bytesIn[Fam4].Add(250_000)
	s.Tick(1e9)
	w0, w1 := sls[0].weight[Fam4], sls[1].weight[Fam4]
	if w0 != 1.0 {
		t.Fatalf("fastest weight = %v, want 1.0", w0)
	}
	if w1 < 0.2 || w1 > 0.3 {
		t.Fatalf("slower weight = %v, want ~0.25", w1)
	}
}

// Weight never drops below the 0.05 floor.
func TestSchedulerWeightFloor(t *testing.T) {
	s := upScheduler(testNets())
	sls := s.snapshot()
	sls[0].bytesIn[Fam4].Add(10_000_000)
	sls[1].bytesIn[Fam4].Add(60_000) // just over minMeasuredPeak
	s.Tick(1e9)
	if w := sls[1].weight[Fam4]; w != 0.05 {
		t.Fatalf("tiny weight = %v, want floor 0.05", w)
	}
}

// Manual weights disable auto measurement.
func TestSchedulerManualDisablesAuto(t *testing.T) {
	s := newScheduler(map[string]float64{"wlan0": 2})
	if s.auto {
		t.Fatal("auto should be off with manual weights")
	}
	s.Update(testNets())
	sls := s.snapshot()
	sls[0].bytesIn[Fam4].Add(10_000_000)
	sls[1].bytesIn[Fam4].Add(10_000_000)
	s.Tick(1e9)
	if sls[0].weight[Fam4] != 2 || sls[1].weight[Fam4] != 1 {
		t.Fatalf("weights = %v/%v, want 2/1", sls[0].weight[Fam4], sls[1].weight[Fam4])
	}
}

// A network with no address for the family is never picked for it.
func TestSchedulerSkipsFamilyWithoutAddress(t *testing.T) {
	nets := testNets()
	nets[1].IPv4 = "" // cellular v4-less
	s := upScheduler(nets)
	for i := 0; i < 20; i++ {
		sl := s.AcquireFor(Fam4, nil)
		if sl == nil {
			t.Fatal("nil")
		}
		if sl.ID != "101" {
			t.Fatalf("picked %s without v4", sl.ID)
		}
		s.ReleaseFor(sl, Fam4)
	}
	if s.AcquireFor(Fam6, nil) != nil {
		t.Fatal("v6 acquire should be nil with no v6 addresses")
	}
}
