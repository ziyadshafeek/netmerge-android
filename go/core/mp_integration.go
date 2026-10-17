package core

import "netmerge/core/multipath"

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

// newMultipathEngine creates the on-phone compounding engine using the
// Kotlin protector as the socket binder.
func (e *Engine) newMultipathEngine() {
	binder := &protectorBinder{p: e.protector}
	e.mpEngine = multipath.NewOnPhoneCompoundEngine(binder)
}
