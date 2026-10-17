package multipath

import (
	"sync"
	"testing"
	"time"
)

// With equal seeds Wi-Fi wins ties (lower seeded RTT).
func TestPickOptimalLinkPrefersFasterLink(t *testing.T) {
	s := NewECTScheduler()
	if got := s.PickOptimalLink(1024 * 1024); got != LinkWiFi {
		t.Fatalf("expected LinkWiFi with fresh seeds, got %v", got)
	}
}

// A much faster cellular link must win despite the Wi-Fi-favoring seeds.
func TestPickOptimalLinkCellularWhenFaster(t *testing.T) {
	s := NewECTScheduler()
	// Train cellular to 100 MB/s with 20ms RTT.
	for i := 0; i < 50; i++ {
		s.Cell.RecordTransfer(10*1024*1024, 100*time.Millisecond)
		s.Cell.RecordRTT(20 * time.Millisecond)
	}
	// Drag Wi-Fi down to ~1 MB/s with 200ms RTT.
	for i := 0; i < 50; i++ {
		s.WiFi.RecordTransfer(1024*1024, time.Second)
		s.WiFi.RecordRTT(200 * time.Millisecond)
	}
	if got := s.PickOptimalLink(4 * 1024 * 1024); got != LinkCellular {
		t.Fatalf("expected LinkCellular after training, got %v", got)
	}
}

// A big in-flight backlog on the fast link shifts new work to the slower one.
func TestInFlightBacklogShiftsDecision(t *testing.T) {
	s := NewECTScheduler()
	// Make cellular clearly faster (both bandwidth and RTT).
	for i := 0; i < 50; i++ {
		s.Cell.RecordTransfer(50*1024*1024, 100*time.Millisecond)
		s.Cell.RecordRTT(10 * time.Millisecond)
	}
	if got := s.PickOptimalLink(1024); got != LinkCellular {
		t.Fatalf("precondition: expected LinkCellular, got %v", got)
	}
	// Pile 500MB of backlog onto cellular: its ECT must now exceed Wi-Fi's.
	s.Cell.AddInFlight(500 * 1024 * 1024)
	if got := s.PickOptimalLink(1024); got != LinkWiFi {
		t.Fatalf("expected LinkWiFi after backlog, got %v", got)
	}
	// Releasing the backlog restores the original decision.
	s.Cell.AddInFlight(-500 * 1024 * 1024)
	if got := s.Cell.InFlight(); got != 0 {
		t.Fatalf("expected inFlight 0 after release, got %d", got)
	}
	if got := s.PickOptimalLink(1024); got != LinkCellular {
		t.Fatalf("expected LinkCellular after release, got %v", got)
	}
}

// RTT EWMA moves toward samples with alpha 0.2 and ignores garbage.
func TestRecordRTTUpdates(t *testing.T) {
	s := NewECTScheduler()
	before := s.WiFi.EstimateCompletionTime(0)
	s.WiFi.RecordRTT(150 * time.Millisecond) // much worse than 15ms seed
	after := s.WiFi.EstimateCompletionTime(0)
	if after <= before {
		t.Fatalf("expected ECT to rise after bad RTT sample: before=%v after=%v", before, after)
	}
	// Non-positive samples must not move the estimate.
	s.WiFi.RecordRTT(0)
	s.WiFi.RecordRTT(-time.Second)
	if got := s.WiFi.EstimateCompletionTime(0); got != after {
		t.Fatalf("garbage RTT samples changed ECT: %v -> %v", after, got)
	}
}

// Tiny transfers don't pollute the goodput estimate.
func TestRecordTransferIgnoresSmall(t *testing.T) {
	s := NewECTScheduler()
	before := s.WiFi.EstimateCompletionTime(1024 * 1024)
	s.WiFi.RecordTransfer(100, time.Hour) // 100 bytes in an hour: absurdly slow
	if got := s.WiFi.EstimateCompletionTime(1024 * 1024); got != before {
		t.Fatalf("sub-16KB transfer moved goodput: %v -> %v", before, got)
	}
}

// Goodput floor keeps ECT finite even for a dead link.
func TestEstimateCompletionTimeFloor(t *testing.T) {
	m := &LinkMetrics{} // zero value: 0 RTT, 0 goodput
	if got := m.EstimateCompletionTime(1024 * 1024); got <= 0 || got > 1e9 {
		t.Fatalf("ECT out of sane range for zero metrics: %v", got)
	}
	// 1MB at floored 64KB/s = 16s + 0 RTT.
	if got := m.EstimateCompletionTime(1024 * 1024); got != 16.0 {
		t.Fatalf("expected exactly 16.0s at floor, got %v", got)
	}
}

// Concurrent recorders must not race (run with -race).
func TestConcurrentAccess(t *testing.T) {
	s := NewECTScheduler()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.WiFi.RecordRTT(time.Duration(10+i) * time.Millisecond)
				s.WiFi.RecordTransfer(32*1024, 10*time.Millisecond)
				s.WiFi.AddInFlight(1024)
				_ = s.PickOptimalLink(4096)
				s.WiFi.AddInFlight(-1024)
			}
		}(i)
	}
	wg.Wait()
}
