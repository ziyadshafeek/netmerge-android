package core

import "net"

// dnsServerFor picks the DNS server a port-53 flow should use: the chosen
// network's first DNS server for the flow's family, falling back to any DNS
// server the network has, or nil to keep the original destination.
//
// Why rewrite: a DNS query sent out of wlan0 but addressed to the cellular
// DNS (or vice versa) either leaks across links or gets dropped by the
// carrier. Rewriting keeps DNS on the same link the scheduler picked.
func (e *Engine) dnsServerFor(sl *Slot, f Family) net.IP {
	var fallback net.IP
	for _, dns := range sl.DNS {
		is4 := dns.To4() != nil
		if (f == Fam4 && is4) || (f == Fam6 && !is4) {
			return dns
		}
		if fallback == nil {
			fallback = dns
		}
	}
	return fallback
}
