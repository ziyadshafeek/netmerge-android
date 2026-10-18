package core

import "netmerge/core/multipath"
import "syscall"

// engineRef is the global Engine reference for the protectorBinder's OnBytes
// callback. Set by newMultipathEngine.
var engineRef *Engine

// protectorBinder adapts core.Protector to multipath.SocketBinder.
type protectorBinder struct {
	p Protector
}

func (b *protectorBinder) BindAndProtect(fd int64, networkType int) bool {
	if b.p == nil {
		return false
	}
	if b.p.BindAndProtect(int(fd), networkType) {
		return true
	}
	// Kotlin had no live Network ref (cold start / transient onLost gap):
	// protect from the VPN and let the OS route instead of aborting the
	// dial. Mirrors core.dialBound's unpinned fallback; the socket stays
	// protected so there is no routing loop.
	b.p.Protect(int(fd))
	return true
}

// CanBindLink is the STRICT link-liveness probe: it checks both AF_INET and
// AF_INET6 so IPv6-only cellular links (e.g. Jio 4G before 464XLAT/clatd
// finishes attaching) are never falsely marked dead during 5G -> 4G handovers.
// It calls the Kotlin bindAndProtect WITHOUT the Protect fallback, so a dead
// radio (null Network ref) reports false. Used for single- vs dual-radio decisions.
func (b *protectorBinder) CanBindLink(networkType int) bool {
	if b.p == nil {
		return false
	}
	for _, domain := range []int{syscall.AF_INET, syscall.AF_INET6} {
		fd, err := syscall.Socket(domain, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			continue
		}
		ok := b.p.BindAndProtect(int(fd), networkType)
		_ = syscall.Close(fd)
		if ok {
			return true
		}
	}
	return false
}

// OnBytes wires VIP flow byte counters back to the Scheduler slots so the
// UI shows real compounded throughput (not dummy counters).
func (b *protectorBinder) OnBytes(networkType int, rxBytes, txBytes int64) {
	if b.p == nil {
		return
	}
	// The Engine holds the scheduler; we need a reference to it.
	// This is set by newMultipathEngine.
	if engineRef != nil && engineRef.scheduler != nil {
		var slotID string
		switch networkType {
		case 1:
			slotID = "wifi"
		case 2:
			slotID = "cellular"
		default:
			return
		}
		if sl := engineRef.scheduler.SlotByID(slotID); sl != nil {
			// Determine family from the bytes? For now, add to both
			// families' counters - the UI aggregates them.
			sl.bytesIn[Fam4].Add(rxBytes)
			sl.bytesOut[Fam4].Add(txBytes)
			sl.bytesIn[Fam6].Add(rxBytes)
			sl.bytesOut[Fam6].Add(txBytes)
		}
	}
}

// newMultipathEngine creates the on-phone compounding engine using the
// Kotlin protector as the socket binder.
func (e *Engine) newMultipathEngine() {
	engineRef = e
	binder := &protectorBinder{p: e.protector}
	e.mpEngine = multipath.NewOnPhoneCompoundEngine(binder)
}
