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

	// Suppress AAAA (28), SVCB (64), and HTTPS (65) with instant NODATA
	// so Chrome/YouTube always use the compounded IPv4 VIPs.
	if qtype == 28 || qtype == 64 || qtype == 65 {
		resp := make([]byte, 0, pos+4)
		resp = append(resp, query[0:2]...)
		resp = append(resp, 0x81, 0x80)
		resp = append(resp, 0x00, 0x01)
		resp = append(resp, 0x00, 0x00)
		resp = append(resp, 0x00, 0x00)
		resp = append(resp, 0x00, 0x00)
		resp = append(resp, query[12:pos+4]...)
		return resp
	}

	if qtype != 1 {
		return nil
	}

	hostname := strings.Join(labels, ".")
	if hostname == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	vip, _ := d.resolver.GetOrAllocateVIP(ctx, hostname)
	if vip == nil {
		return nil
	}

	resp := make([]byte, 0, pos+20)
	resp = append(resp, query[0:2]...)
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, query[12:pos+4]...)

	// Answer with TTL = 2 seconds so parallel fetches rotate across the VIP ring
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x02) // TTL = 2s
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, vip.To4()...)
	return resp
}

func (d *DNSInterceptor) LookupVIP(ipStr string) *DualEndpoint {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	return d.resolver.EndpointForVIP(ip)
}
