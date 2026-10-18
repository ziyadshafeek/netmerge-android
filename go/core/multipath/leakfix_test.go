package multipath

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestFilterIPv4Only(t *testing.T) {
	in := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2606:4700:4700::1111"),
		net.ParseIP("9.9.9.9"),
	}
	out := filterIPv4Only(in)
	if len(out) != 2 {
		t.Fatalf("filterIPv4Only: got %d, want 2", len(out))
	}
	for _, ip := range out {
		if ip.To4() == nil {
			t.Fatalf("filterIPv4Only leaked IPv6: %v", ip)
		}
	}
}

func TestIsKnownAAAAOnlyDomain(t *testing.T) {
	for _, d := range []string{"ipv6.browserleaks.com", "a.ipv6.browserleaks.com", "test-ipv6.com"} {
		if !isKnownAAAAOnlyDomain(d) {
			t.Fatalf("should match AAAA-only beacon: %s", d)
		}
	}
	for _, d := range []string{"browserleaks.com", "www.google.com", "ipv6.browserleaks.com.evil.com"} {
		if isKnownAAAAOnlyDomain(d) {
			t.Fatalf("false positive on: %s", d)
		}
	}
}

func TestNodataResponseShape(t *testing.T) {
	// Minimal A-query for example.com
	var q []byte
	q = append(q, 0x12, 0x34)             // ID
	q = append(q, 0x01, 0x00)             // flags RD
	q = append(q, 0x00, 0x01)             // QDCOUNT=1
	q = append(q, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR = 0
	for _, l := range []string{"example", "com"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0x00)
	q = append(q, 0x00, 0x01) // QTYPE=A
	q = append(q, 0x00, 0x01) // QCLASS=IN
	pos := len(q) - 4
	resp := nodataResponse(q, pos)
	if len(resp) < 12 {
		t.Fatal("response too short")
	}
	if binary.BigEndian.Uint16(resp[2:4])&0x000F != 0 {
		t.Fatal("NODATA must carry RCODE=0 (NOERROR)")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Fatal("NODATA must carry ANCOUNT=0")
	}
	if !bytes.Equal(resp[0:2], q[0:2]) {
		t.Fatal("ID mismatch")
	}
}

func TestWriteFragmentedClientHelloSplitsTCPSegments(t *testing.T) {
	hello := buildTestClientHello()
	cc := &chunkConn{}
	n, err := writeFragmentedClientHello(cc, hello)
	if err != nil || n != len(hello) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !bytes.Equal(cc.buf.Bytes(), hello) {
		t.Fatal("wire bytes must equal the original ClientHello exactly")
	}
	if len(cc.chunks) < 2 {
		t.Fatalf("expected >=2 TCP chunks, got %v", cc.chunks)
	}
	// No TLS record re-framing: the first 5 bytes must be the ORIGINAL record header.
	if !bytes.Equal(cc.buf.Bytes()[:5], hello[:5]) {
		t.Fatal("TLS record header was re-framed")
	}
}
