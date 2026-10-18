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
	// Verify exactly 2 TLS records were emitted, neither using suspicious 0x0302 (TLS 1.1),
	// and that reassembled handshake bytes match the original ClientHello 100%.
	var reassembled []byte
	offset := 0
	records := 0
	for offset < len(received) {
		if offset+5 > len(received) {
			t.Fatalf("truncated record header at %d", offset)
		}
		if received[offset] != 0x16 {
			t.Fatalf("unexpected record type 0x%02x", received[offset])
		}
		if received[offset+1] != 0x03 || (received[offset+2] != 0x01 && received[offset+2] != 0x03) {
			t.Fatalf("suspicious record version 0x%02x%02x", received[offset+1], received[offset+2])
		}
		rLen := int(binary.BigEndian.Uint16(received[offset+3 : offset+5]))
		reassembled = append(reassembled, received[offset+5:offset+5+rLen]...)
		offset += 5 + rLen
		records++
	}
	if records != 2 {
		t.Fatalf("expected 2 clean TLS records, got %d", records)
	}
	if !bytes.Equal(reassembled, orig[5:]) {
		t.Fatalf("reassembled ClientHello handshake payload mismatch")
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
