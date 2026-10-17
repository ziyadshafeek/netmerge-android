// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

// OnPhoneCompoundEngine is the top-level coordinator for on-phone bandwidth
// compounding. It owns the VIP resolver (DNS anti-coalescing), the ECT
// scheduler (link selection), the halving splicer (HTTP range compounding),
// and the QUIC guard (bulk QUIC eviction).
type OnPhoneCompoundEngine struct {
	Binder    SocketBinder
	Resolver  *VIPResolver
	Scheduler *ECTScheduler
	Splicer   *HalvingSplicer
	QUICGuard *ElephantQUICGuard
	DNS       *DNSInterceptor
	MPSched   *Scheduler
	Racer     *Racer
}

// NewOnPhoneCompoundEngine creates a compounding engine. The binder is the
// Android Network.bindSocket bridge (may be nil for testing, in which case
// dials will fail).
func NewOnPhoneCompoundEngine(binder SocketBinder) *OnPhoneCompoundEngine {
	resolver := NewVIPResolver(binder)
	sched := NewScheduler()
	return &OnPhoneCompoundEngine{
		Binder:    binder,
		Resolver:  resolver,
		Scheduler: NewECTScheduler(),
		Splicer:   NewHalvingSplicer(binder),
		QUICGuard: NewElephantQUICGuard(),
		DNS:       NewDNSInterceptor(resolver),
		MPSched:   sched,
		Racer:     NewRacer(binder, resolver, sched),
	}
}
