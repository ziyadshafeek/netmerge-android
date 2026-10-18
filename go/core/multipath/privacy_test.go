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

// chunkConn records each Write call's byte count so tests can verify TCP-level
// chunking (SNI split across segments) without TLS record fragmentation.
type chunkConn struct {
	captureConn
	chunks []int
}

func (c *chunkConn) Write(b []byte) (int, error) {
	c.chunks = append(c.chunks, len(b))
	return c.captureConn.Write(b)
}

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

	cc := &chunkConn{}
	n, err := WriteClientHello(cc, hello)
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	if n != len(hello) {
		t.Fatalf("wrote %d bytes, want %d", n, len(hello))
	}
	out := cc.buf.Bytes()

	// New contract: the TLS record stays WHOLE (single 0x16 record, JA3/JA4
	// parseable) but is split across multiple TCP writes so the SNI hostname
	// is never contiguous in one IP packet.
	if !bytes.Equal(out, hello) {
		t.Fatalf("output differs from input: got %d bytes, want %d", len(out), len(hello))
	}
	if len(cc.chunks) < 2 {
		t.Fatalf("expected TCP-level chunking, got %d write(s)", len(cc.chunks))
	}
	// Verify a chunk boundary falls strictly inside the SNI hostname.
	hostOff := bytes.Index(payload, []byte("example.com"))
	if hostOff < 0 {
		t.Fatal("SNI hostname not found in payload")
	}
	hostStart, hostEnd := 5+hostOff, 5+hostOff+len("example.com")
	boundary := 0
	splitInside := false
	for _, cl := range cc.chunks {
		boundary += cl
		if boundary > hostStart && boundary < hostEnd {
			splitInside = true
			break
		}
	}
	if !splitInside {
		t.Fatalf("no chunk boundary inside SNI hostname (chunks=%v)", cc.chunks)
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

func TestIsInvalidTLSResponse(t *testing.T) {
	hello := buildTestClientHello()
	// Valid ServerHello (0x16) -> not invalid.
	if isInvalidTLSResponse(hello, []byte{0x16, 0x03, 0x03, 0x00, 0x10}) {
		t.Fatal("valid ServerHello flagged invalid")
	}
	// TLS Alert (0x15) -> invalid, must replay.
	if !isInvalidTLSResponse(hello, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) {
		t.Fatal("TLS Alert not flagged invalid")
	}
	// Plain HTTP error -> invalid, must replay.
	if !isInvalidTLSResponse(hello, []byte("HTTP/1.1 400 Bad Request\r\n")) {
		t.Fatal("HTTP error not flagged invalid")
	}
	// Empty read -> invalid.
	if !isInvalidTLSResponse(hello, nil) {
		t.Fatal("empty response not flagged invalid")
	}
	// Non-TLS payload -> never invalid (guard only applies to handshakes).
	if isInvalidTLSResponse([]byte("GET / HTTP/1.1"), []byte{0x15}) {
		t.Fatal("non-TLS payload flagged invalid")
	}
}
