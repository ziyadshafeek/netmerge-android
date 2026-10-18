package core

import (
	"netmerge/core/multipath"
	"syscall"
)

var engineRef *Engine

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
	b.p.Protect(int(fd))
	return true
}

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

// OnBytes wires VIP flow byte counters back to the Scheduler slots once per
// active family (fixing the 2x byte inflation where both Fam4 and Fam6 were incremented).
func (b *protectorBinder) OnBytes(networkType int, rxBytes, txBytes int64) {
	if b.p == nil || engineRef == nil || engineRef.scheduler == nil {
		return
	}
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
		fam := Fam4
		if sl.ip(Fam4) == nil && sl.ip(Fam6) != nil {
			fam = Fam6
		}
		sl.bytesIn[fam].Add(rxBytes)
		sl.bytesOut[fam].Add(txBytes)
	}
}

func (e *Engine) newMultipathEngine() {
	engineRef = e
	multipath.SetFlowHook(func(link multipath.LinkType, delta int64) {
		if engineRef == nil || engineRef.scheduler == nil {
			return
		}
		slotID := "wifi"
		if link == multipath.LinkCellular {
			slotID = "cellular"
		}
		if sl := engineRef.scheduler.SlotByID(slotID); sl != nil {
			sl.active.Add(delta)
			if delta > 0 {
				sl.total.Add(delta)
			}
		}
	})
	binder := &protectorBinder{p: e.protector}
	e.mpEngine = multipath.NewOnPhoneCompoundEngine(binder)
}
