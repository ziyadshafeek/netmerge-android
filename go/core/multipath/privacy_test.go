package multipath

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// captureConn records everything written; setSocketMaxSeg no-ops on it
// (no syscall.Conn), so the shattering path is fully exercised.
type captureConn struct{ buf bytes.Buffer }

func (c *captureConn) Write(b []byte) (int, error)        { return c.buf.Write(b) }
func (c *captureConn) Read(b []byte) (int, error)         { return 0, nil }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return nil }
func (c *captureConn) RemoteAddr() net.Addr               { return nil }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

// buildTestClientHello crafts a minimal but structurally valid TLS 1.2
// ClientHello carrying an SNI extension for "example.com".
func buildTestClientHello() []byte {
	hostname := []byte("example.com")
	// server_name entry: type(0x00) + len + hostname
	var snEntry []byte
	snEntry = append(snEntry, 0x00)
	var nameLen [2]byte
	binary.BigEndian.PutUint16(nameLen[:], uint16(len(hostname)))
	snEntry = append(snEntry, nameLen[:]...)
	snEntry = append(snEntry, hostname...)
	// server_name_list: len + entries
	var snList []byte
	var listLen [2]byte
	binary.BigEndian.PutUint16(listLen[:], uint16(len(snEntry)))
	snList = append(snList, listLen[:]...)
	snList = append(snList, snEntry...)
	// SNI extension: type(0x0000) + len + snList
	var sniExt []byte
	sniExt = append(sniExt, 0x00, 0x00)
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(snList)))
	sniExt = append(sniExt, extLen[:]...)
	sniExt = append(sniExt, snList...)

	// Handshake body
	var body []byte
	body = append(body, 0x03, 0x03)             // client version TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression methods
	var allExtLen [2]byte
	binary.BigEndian.PutUint16(allExtLen[:], uint16(len(sniExt)))
	body = append(body, allExtLen[:]...)
	body = append(body, sniExt...)

	// Handshake header: type(0x01) + 3-byte length
	var hs []byte
	hs = append(hs, 0x01)
	hsLen := len(body)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	// TLS record header: 0x16 0x03 0x01 + 2-byte length
	var rec []byte
	rec = append(rec, 0x16, 0x03, 0x01)
	var recLen [2]byte
	binary.BigEndian.PutUint16(recLen[:], uint16(len(hs)))
	rec = append(rec, recLen[:]...)
	rec = append(rec, hs...)
	return rec
}

func TestShatteredClientHelloPreservesTranscript(t *testing.T) {
	hello := buildTestClientHello()
	if !isTLSClientHello(hello) {
		t.Fatal("synthetic ClientHello not recognized")
	}
	payload := hello[5:]
	sniStart, sniEnd := findSNIBounds(payload)
	if sniStart == 0 || sniEnd <= sniStart {
		t.Fatalf("findSNIBounds failed: %d-%d", sniStart, sniEnd)
	}
	if payload[sniStart] != 0x00 || payload[sniStart+1] != 0x00 {
		t.Fatal("SNI extension header not at reported bounds")
	}

	cc := &captureConn{}
	n, err := WriteClientHello(cc, hello)
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	if n != len(hello) {
		t.Fatalf("wrote %d bytes, want %d", n, len(hello))
	}
	out := cc.buf.Bytes()

	// Parse the output as TLS records; concatenating payloads must
	// reproduce the original handshake payload EXACTLY (RFC 8446
	// transcript-hash invariance).
	var reassembled []byte
	recCount := 0
	for off := 0; off < len(out); {
		if off+5 > len(out) {
			t.Fatalf("truncated record header at %d", off)
		}
		if out[off] != 0x16 || out[off+1] != 0x03 {
			t.Fatalf("record %d has bad header: %02x %02x", recCount, out[off], out[off+1])
		}
		rl := int(binary.BigEndian.Uint16(out[off+3 : off+5]))
		if off+5+rl > len(out) {
			t.Fatalf("record %d overruns output", recCount)
		}
		reassembled = append(reassembled, out[off+5:off+5+rl]...)
		off += 5 + rl
		recCount++
	}
	if recCount < 2 {
		t.Fatalf("expected shattering into 2+ records, got %d", recCount)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled payload differs: got %d bytes, want %d", len(reassembled), len(payload))
	}
}

func TestShatteringSkipsNonHello(t *testing.T) {
	plain := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	cc := &captureConn{}
	n, err := WriteClientHello(cc, plain)
	if err != nil || n != len(plain) {
		t.Fatalf("plain write failed: %v %d", err, n)
	}
	if !bytes.Equal(cc.buf.Bytes(), plain) {
		t.Fatal("non-TLS payload was modified")
	}
}

func TestDoHClientsKeyedPerLink(t *testing.T) {
	fb := &fakeBinder{}
	r := NewVIPResolver(fb)
	// https://1.1.1.1/dns-query exists in BOTH provider lists; the cellular
	// client must not overwrite the Wi-Fi one (the pre-fix bug).
	wifiC := r.dohClients[dohClientKey(LinkWiFi, "https://1.1.1.1/dns-query")]
	cellC := r.dohClients[dohClientKey(LinkCellular, "https://1.1.1.1/dns-query")]
	if wifiC == nil || cellC == nil {
		t.Fatal("missing per-link DoH client")
	}
	if wifiC == cellC {
		t.Fatal("cellular DoH client overwrote the Wi-Fi client for 1.1.1.1")
	}
}
