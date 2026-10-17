// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// DNSInterceptor handles UDP/53 queries by returning synthetic VIPs
// (198.18.x.y) for A records, breaking HTTP/2 connection coalescing
// (RFC 9113). The real dual-stack endpoints are resolved in the background.
type DNSInterceptor struct {
	resolver *VIPResolver
}

// NewDNSInterceptor creates a DNS interceptor using the given VIP resolver.
func NewDNSInterceptor(resolver *VIPResolver) *DNSInterceptor {
	return &DNSInterceptor{resolver: resolver}
}

// HandleQuery processes a raw DNS query packet. If it's an A-record query
// for a valid hostname, it returns a DNS response with a synthetic VIP.
// Otherwise it returns nil (caller should forward the query upstream).
func (d *DNSInterceptor) HandleQuery(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	// Parse header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
	id := binary.BigEndian.Uint16(query[0:2])
	flags := binary.BigEndian.Uint16(query[2:4])
	qdcount := binary.BigEndian.Uint16(query[4:6])

	// Only handle standard queries with exactly 1 question
	if flags&0x7800 != 0 || qdcount != 1 {
		return nil
	}

	// Parse QNAME (sequence of length-prefixed labels ending with 0)
	pos := 12
	var labels []string
	for pos < len(query) {
		l := int(query[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			// Compression pointer - not expected in queries
			return nil
		}
		if pos+l > len(query) {
			return nil
		}
		labels = append(labels, string(query[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(query) {
		return nil
	}

	qtype := binary.BigEndian.Uint16(query[pos : pos+2])
	// qclass := binary.BigEndian.Uint16(query[pos+2 : pos+4])

	// Suppress AAAA (28), SVCB (64), and HTTPS (65) with empty NOERROR.
	// Chrome/YouTube send parallel A/AAAA/HTTPS queries. If AAAA or HTTPS
	// go upstream and return real IPv6 or HTTPS hints, Chrome bypasses the
	// 198.18.x.x VIP and connects directly (no compounding). Returning
	// NODATA forces all traffic through the IPv4 VIP -> TCP compounding.
	if qtype == 28 || qtype == 64 || qtype == 65 {
		resp := make([]byte, 0, len(query))
		resp = append(resp, query[0:2]...) // ID
		resp = append(resp, 0x81, 0x80)    // Flags: response, recursion available
		resp = append(resp, 0x00, 0x01)    // QDCOUNT = 1
		resp = append(resp, 0x00, 0x00)    // ANCOUNT = 0 (NODATA)
		resp = append(resp, 0x00, 0x00)    // NSCOUNT = 0
		resp = append(resp, 0x00, 0x00)    // ARCOUNT = 0
		resp = append(resp, query[12:pos+4]...) // Question section
		return resp
	}

	// Only intercept A records (IPv4). Other types go upstream normally.
	if qtype != 1 {
		return nil
	}

	hostname := strings.Join(labels, ".")
	if hostname == "" {
		return nil
	}

	// Allocate VIP (triggers background dual-stack resolution)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vip, _ := d.resolver.GetOrAllocateVIP(ctx, hostname)
	if vip == nil {
		return nil
	}

	// Build response: copy query, set flags, add 1 answer
	resp := make([]byte, 0, len(query)+16)
	resp = append(resp, query[0:2]...) // ID
	resp = append(resp, 0x81, 0x80)    // Flags: response, recursion available
	resp = append(resp, 0x00, 0x01)    // QDCOUNT = 1
	resp = append(resp, 0x00, 0x01)    // ANCOUNT = 1
	resp = append(resp, 0x00, 0x00)    // NSCOUNT = 0
	resp = append(resp, 0x00, 0x00)    // ARCOUNT = 0
	resp = append(resp, query[12:pos+4]...) // Question section

	// Answer: NAME (pointer to QNAME at offset 12), TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4, RDATA=VIP
	resp = append(resp, 0xC0, 0x0C)       // Pointer to QNAME
	resp = append(resp, 0x00, 0x01)       // TYPE = A
	resp = append(resp, 0x00, 0x01)       // CLASS = IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x05) // TTL = 5 (frequent re-query for VIP rotation)
	resp = append(resp, 0x00, 0x04)       // RDLENGTH = 4
	resp = append(resp, vip.To4()...)    // RDATA = VIP

	_ = id // ID is already in the response
	return resp
}

// LookupVIP returns the DualEndpoint for a VIP string (e.g., "198.18.0.5"),
// or nil if it's not a VIP we allocated.
func (d *DNSInterceptor) LookupVIP(ipStr string) *DualEndpoint {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	return d.resolver.EndpointForVIP(ip)
}
