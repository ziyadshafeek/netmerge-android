package multipath

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

func TestODoHRoundTripRFC9230(t *testing.T) {
	// 1. Generate Target X25519 Keypair and serialize RFC 9230 ObliviousDoHConfigs
	skR, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	configsWire := MarshalODoHConfigs(skR.PublicKey())
	// 2. Client parses ObliviousDoHConfigs and derives KeyID
	cfg, err := ParseODoHConfigs(configsWire)
	if err != nil {
		t.Fatalf("ParseODoHConfigs failed: %v", err)
	}
	if len(cfg.KeyID) != 32 {
		t.Fatalf("expected 32-byte SHA-256 KeyID, got %d", len(cfg.KeyID))
	}
	// 3. Build an EDNS0-padded DNS query and seal it with HPKE
	dnsQuery, txID := buildDNSQueryPacket("www.wikipedia.org", 1, true)
	odohQueryWire, clientCtx, err := cfg.SealQuery(dnsQuery)
	if err != nil {
		t.Fatalf("SealQuery failed: %v", err)
	}
	if bytes.Contains(odohQueryWire, []byte("wikipedia")) {
		t.Fatalf("plaintext domain leaked inside encrypted ODoH query!")
	}
	// 4. Target opens the HPKE query, builds a synthetic DNS A-record response,
	// and seals the response using RFC 9230 Section 4.2 exported key material.
	odohRespWire, err := OpenQueryAndSealResponse(skR, cfg, odohQueryWire, func(q []byte) ([]byte, error) {
		if !bytes.Equal(q, dnsQuery) {
			t.Fatalf("decrypted DNS query mismatch")
		}
		// Construct minimal valid DNS response for txID -> 93.184.216.34
		var resp []byte
		var hdr [12]byte
		binary.BigEndian.PutUint16(hdr[0:2], txID)
		binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
		binary.BigEndian.PutUint16(hdr[4:6], 0) // QDCOUNT=0 for compact test answer
		binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT=1
		resp = append(resp, hdr[:]...)
		resp = append(resp, 0x00)                   // root name
		resp = append(resp, 0x00, 0x01, 0x00, 0x01) // TYPE A, CLASS IN
		resp = append(resp, 0x00, 0x00, 0x00, 0x3c) // TTL 60s
		resp = append(resp, 0x00, 0x04)             // RDLENGTH 4
		resp = append(resp, 93, 184, 216, 34)
		return resp, nil
	})
	if err != nil {
		t.Fatalf("OpenQueryAndSealResponse failed: %v", err)
	}
	// 5. Client opens the encrypted ODoH response and parses the resolved IP
	decryptedDNSResp, err := clientCtx.OpenResponse(odohRespWire)
	if err != nil {
		t.Fatalf("OpenResponse failed: %v", err)
	}
	ips := parseDNSResponsePacket(decryptedDNSResp, txID)
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("unexpected resolved IPs: %v", ips)
	}
	// 6. Verify ciphertext tampering is rejected by AES-128-GCM
	odohRespWire[len(odohRespWire)-1] ^= 0xff
	if _, err := clientCtx.OpenResponse(odohRespWire); err == nil {
		t.Fatalf("expected tampered ODoH response to fail AEAD authentication")
	}
}
