package multipath

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

type DNSInterceptor struct {
	resolver *VIPResolver
}

// knownAAAAOnlyDomains are leak-test beacons with no IPv4 A record. Chrome
// fires A + AAAA together for them; handing out a synthetic 198.18.x.x VIP
// would make Chrome attempt TCP to the VIP and then fail. Answer NODATA
// instead so the beacon fails fast without any connection attempt.
var knownAAAAOnlyDomains = []string{
	"ipv6.browserleaks.com",
	"ipv6-test.com",
	"test-ipv6.com",
}

func isKnownAAAAOnlyDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range knownAAAAOnlyDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func NewDNSInterceptor(resolver *VIPResolver) *DNSInterceptor {
	return &DNSInterceptor{resolver: resolver}
}

func (d *DNSInterceptor) HandleQuery(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	flags := binary.BigEndian.Uint16(query[2:4])
	qdcount := binary.BigEndian.Uint16(query[4:6])

	if flags&0x7800 != 0 || qdcount != 1 {
		return nil
	}

	pos := 12
	var labels []string
	for pos < len(query) {
		l := int(query[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || pos+l > len(query) {
			return nil
		}
		labels = append(labels, string(query[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(query) {
		return nil
	}

	qtype := binary.BigEndian.Uint16(query[pos : pos+2])

	// Return instant NODATA (NOERROR, ANCOUNT=0) for ALL non-A record types
	// (AAAA=28, SVCB=64, HTTPS=65, TXT=16, SRV=33, PTR=12, MX=15, etc.) so
	// upstream-free DNS interception never drops packets or stalls apps.
	if qtype != 1 {
		return nodataResponse(query, pos)
	}

	hostname := strings.Join(labels, ".")
	if hostname == "" {
		return nil
	}

	// Known AAAA-only beacons: NODATA before any VIP is allocated, so no
	// synthetic 198.18.x.x is ever handed out and no refresh storm starts.
	if isKnownAAAAOnlyDomain(hostname) {
		return nodataResponse(query, pos)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	vip, ep := d.resolver.GetOrAllocate(ctx, hostname)
	// Cached endpoint that resolved zero IPv4 A records: NODATA instead of a
	// synthetic VIP (the TCP path would only fail closed anyway).
	if ep != nil && ep.IsReady() && !ep.HasIPv4() {
		return nodataResponse(query, pos)
	}
	if vip == nil {
		// Return instant SERVFAIL (RCODE=2) instead of nil so apps fail fast
		// rather than hanging for 5-15s waiting for a dropped UDP packet.
		resp := make([]byte, 0, pos+4)
		resp = append(resp, query[0:2]...)
		resp = append(resp, 0x81, 0x82) // RCODE=2 (SERVFAIL)
		resp = append(resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		resp = append(resp, query[12:pos+4]...)
		return resp
	}

	resp := make([]byte, 0, pos+20)
	resp = append(resp, query[0:2]...)
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, query[12:pos+4]...)

	// Answer with TTL = 2 seconds so parallel fetches rotate across the VIP ring.
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x02) // TTL = 2s
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, vip.To4()...)
	return resp
}

// nodataResponse builds an instant NODATA reply (NOERROR, ANCOUNT=0).
func nodataResponse(query []byte, pos int) []byte {
	resp := make([]byte, 0, pos+4)
	resp = append(resp, query[0:2]...)
	resp = append(resp, 0x81, 0x80) // QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
	resp = append(resp, 0x00, 0x01) // QDCOUNT=1
	resp = append(resp, 0x00, 0x00) // ANCOUNT=0
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, query[12:pos+4]...)
	return resp
}

func (d *DNSInterceptor) LookupVIP(ipStr string) *DualEndpoint {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	if ep, ok := d.resolver.LookupVIP(ip); ok {
		return ep
	}
	return nil
}
