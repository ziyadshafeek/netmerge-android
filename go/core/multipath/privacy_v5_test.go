package multipath

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestBuildProbeClientHelloIsValidTLS13(t *testing.T) {
	pkt := BuildProbeClientHello("www.cloudflare.com")
	if len(pkt) < 90 {
		t.Fatalf("probe ClientHello too short: %d", len(pkt))
	}
	if pkt[0] != 0x16 || pkt[1] != 0x03 || pkt[5] != 0x01 {
		t.Fatalf("invalid TLS ClientHello header: %x", pkt[:6])
	}
	s, e := findSNIBounds(pkt[5:])
	if e <= s {
		t.Fatalf("SNI extension not found in probe ClientHello")
	}
}

func TestWriteFragmentedClientHelloHerdConformant(t *testing.T) {
	orig := BuildProbeClientHello("chat.openai.com")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	var received []byte
	done := make(chan error, 1)
	go func() {
		buf, err := io.ReadAll(c2)
		received = buf
		done <- err
	}()
	n, err := writeFragmentedClientHello(c1, orig)
	_ = c1.Close()
	if err != nil || n != len(orig) {
		t.Fatalf("writeFragmentedClientHello failed: n=%d err=%v", n, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read failed: %v", err)
	}
	// The TLS record must stay whole and byte-identical (JA3/JA4 parseable);
	// SNI evasion happens at TCP segment boundaries, not via record splits.
	if !bytes.Equal(received, orig) {
		t.Fatalf("wire bytes differ from original ClientHello")
	}
	if len(received) < 6 || received[0] != 0x16 {
		t.Fatalf("not a single TLS handshake record on the wire")
	}
}

func TestMorphingConnPreservesTLSAppDataStream(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	mc := WrapMorphingConn(c1, LinkWiFi)
	// Simulate an encrypted TLS 1.3 Application Data record (0x17 0x03 0x03 + 1200B payload)
	appRecord := make([]byte, 1205)
	appRecord[0] = 0x17
	appRecord[1] = 0x03
	appRecord[2] = 0x03
	binary.BigEndian.PutUint16(appRecord[3:5], 1200)
	GlobalPrivacy.FillCryptoRandom(appRecord[5:])
	var reads []int
	var received []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, err := c2.Read(buf)
			if n > 0 {
				reads = append(reads, n)
				received = append(received, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	n, err := mc.Write(appRecord)
	_ = mc.Close()
	<-done
	if err != nil || n != len(appRecord) {
		t.Fatalf("MorphingConn.Write failed: n=%d err=%v", n, err)
	}
	if len(reads) != 2 {
		t.Fatalf("expected L4 segment split into 2 writes, got %d (%v)", len(reads), reads)
	}
	if !bytes.Equal(received, appRecord) {
		t.Fatalf("MorphingConn altered encrypted TLS stream bytes!")
	}
}

func TestWriteClientHelloOnMorphingConnSingleFragment(t *testing.T) {
	// Regression test: WriteClientHello called on a MorphingConn (the real
	// compound_engine.go path) must emit the ClientHello byte-identical —
	// MorphingConn must never re-slice or corrupt the handshake.
	orig := BuildProbeClientHello("example.com")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	mc := WrapMorphingConn(c1, LinkCellular)
	var received []byte
	done := make(chan error, 1)
	go func() {
		buf, err := io.ReadAll(c2)
		received = buf
		done <- err
	}()
	n, err := WriteClientHello(mc, orig)
	_ = mc.Close()
	if err != nil || n != len(orig) {
		t.Fatalf("WriteClientHello failed: n=%d err=%v", n, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(received, orig) {
		t.Fatalf("wire bytes differ from original ClientHello (handshake corrupted)")
	}
}
