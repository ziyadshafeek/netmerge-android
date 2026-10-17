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
	return b.p.BindAndProtect(int(fd), networkType)
}

// newMultipathEngine creates the on-phone compounding engine using the
// Kotlin protector as the socket binder.
func (e *Engine) newMultipathEngine() {
	binder := &protectorBinder{p: e.protector}
	e.mpEngine = multipath.NewOnPhoneCompoundEngine(binder)
}
