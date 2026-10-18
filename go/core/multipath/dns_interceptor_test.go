package multipath

import (
	"context"
	"encoding/binary"
	"testing"
)

// buildDNSQuery crafts a minimal DNS query for domain/qtype.
func buildDNSQuery(domain string, qtype uint16) []byte {
	var q []byte
	q = append(q, 0x12, 0x34) // txid
	q = append(q, 0x01, 0x00) // flags: RD
	q = append(q, 0x00, 0x01) // qdcount=1
	q = append(q, 0x00, 0x00) // ancount
	q = append(q, 0x00, 0x00) // nscount
	q = append(q, 0x00, 0x00) // arcount
	for _, l := range splitLabels(domain) {
		q = append(q, byte(len(l)))
		q = append(q, []byte(l)...)
	}
	q = append(q, 0x00)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], qtype)
	binary.BigEndian.PutUint16(qt[2:4], 1)
	q = append(q, qt[:]...)
	return q
}

func splitLabels(d string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(d); i++ {
		if i == len(d) || d[i] == '.' {
			out = append(out, d[start:i])
			start = i + 1
		}
	}
	return out
}

func TestInterceptorNeverDropsNonAQueries(t *testing.T) {
	fb := &fakeBinder{}
	r := NewVIPResolver(fb)
	// Resolver that always fails: forces the vip==nil path.
	r.resolve = func(ctx context.Context, domain string) (string, string) { return "", "" }
	di := NewDNSInterceptor(r)

	// TXT/SRV/MX/PTR must get instant NODATA, never nil (nil = 5-15s app hang
	// now that there is no upstream UDP/53 socket).
	for _, qt := range []uint16{16, 33, 15, 12, 255} {
		resp := di.HandleQuery(buildDNSQuery("example.com", qt))
		if resp == nil {
			t.Fatalf("qtype %d: got nil, want instant NODATA", qt)
		}
		if binary.BigEndian.Uint16(resp[2:4])&0x000F != 0 {
			t.Fatalf("qtype %d: want RCODE 0, got %d", qt, binary.BigEndian.Uint16(resp[2:4])&0x000F)
		}
		if binary.BigEndian.Uint16(resp[6:8]) != 0 {
			t.Fatalf("qtype %d: want ANCOUNT 0", qt)
		}
	}

	// A query with unresolvable domain must get SERVFAIL, never nil.
	resp := di.HandleQuery(buildDNSQuery("unresolvable.invalid", 1))
	if resp == nil {
		t.Fatal("A query on dead resolver: got nil, want SERVFAIL")
	}
	if binary.BigEndian.Uint16(resp[2:4])&0x000F != 2 {
		t.Fatalf("want RCODE 2 (SERVFAIL), got %d", binary.BigEndian.Uint16(resp[2:4])&0x000F)
	}
}

func TestNextAddrsRotatesPools(t *testing.T) {
	ep := &DualEndpoint{
		Domain:   "example.com",
		WiFiAddr: "1.1.1.1",
		CellAddr: "2.2.2.2",
		WiFiPool: []string{"1.1.1.1", "1.0.0.1"},
		CellPool: []string{"2.2.2.2", "3.3.3.3"},
	}
	seenW := map[string]bool{}
	seenC := map[string]bool{}
	for i := 0; i < 6; i++ {
		w, c := ep.NextAddrs()
		seenW[w] = true
		seenC[c] = true
	}
	if len(seenW) != 2 || len(seenC) != 2 {
		t.Fatalf("pools did not rotate: wifi=%v cell=%v", seenW, seenC)
	}
	// Empty pools fall back to the primary addrs.
	ep2 := &DualEndpoint{WiFiAddr: "9.9.9.9", CellAddr: "8.8.8.8"}
	w, c := ep2.NextAddrs()
	if w != "9.9.9.9" || c != "8.8.8.8" {
		t.Fatalf("fallback addrs wrong: %s %s", w, c)
	}
}
