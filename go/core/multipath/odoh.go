package multipath

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RFC 9230 & RFC 9180 Constants for ODoH v1:
// KEM: DHKEM(X25519, HKDF-SHA256) = 0x0020
// KDF: HKDF-SHA256 = 0x0001
// AEAD: AES-128-GCM = 0x0001
const (
	odohVersion     uint16 = 0x0001
	hpkeKEMX255     uint16 = 0x0020
	hpkeKDF256      uint16 = 0x0001
	hpkeAEAD128     uint16 = 0x0001
	hpkeNk                 = 16 // AES-128-GCM key size
	hpkeNn                 = 12 // AES-128-GCM nonce size
	hpkeNh                 = 32 // SHA-256 hash output size
	odohMsgQuery    byte   = 0x01
	odohMsgResponse byte   = 0x02
)

var (
	errODoHInvalidConfig   = errors.New("odoh: no supported X25519-HKDF-AES128GCM config")
	errODoHMalformedPacket = errors.New("odoh: malformed wire message")
	errODoHResponseType    = errors.New("odoh: unexpected message type")
)

// ODoHConfig holds a parsed RFC 9230 ObliviousDoHConfig and its derived KeyID.
type ODoHConfig struct {
	KEMID       uint16
	KDFID       uint16
	AEADID      uint16
	PublicKey   *ecdh.PublicKey
	RawKeyBytes []byte
	RawConfig   []byte
	KeyID       []byte
	FetchedAt   time.Time
}

// ODoHClientContext holds the per-query HPKE state required to decrypt the
// target's ObliviousDoHMessage response (RFC 9230 Section 4.2).
type ODoHClientContext struct {
	exporterSecret []byte
	queryPlaintext []byte
}

// ParseODoHConfigs parses an RFC 9230 ObliviousDoHConfigs wire structure
// (as served by /.well-known/odohconfigs) and selects the first config matching
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
func ParseODoHConfigs(wire []byte) (*ODoHConfig, error) {
	if len(wire) < 4 {
		return nil, errODoHInvalidConfig
	}
	totalLen := int(binary.BigEndian.Uint16(wire[0:2]))
	if len(wire) < 2+totalLen {
		return nil, errODoHInvalidConfig
	}
	buf := wire[2 : 2+totalLen]
	for len(buf) >= 4 {
		ver := binary.BigEndian.Uint16(buf[0:2])
		cLen := int(binary.BigEndian.Uint16(buf[2:4]))
		if len(buf) < 4+cLen {
			break
		}
		contents := buf[4 : 4+cLen]
		buf = buf[4+cLen:]
		if ver != odohVersion || len(contents) < 8 {
			continue
		}
		kemID := binary.BigEndian.Uint16(contents[0:2])
		kdfID := binary.BigEndian.Uint16(contents[2:4])
		aeadID := binary.BigEndian.Uint16(contents[4:6])
		pkLen := int(binary.BigEndian.Uint16(contents[6:8]))
		if len(contents) != 8+pkLen {
			continue
		}
		if kemID == hpkeKEMX255 && kdfID == hpkeKDF256 && aeadID == hpkeAEAD128 && pkLen == 32 {
			pubBytes := append([]byte(nil), contents[8:8+pkLen]...)
			pubKey, err := ecdh.X25519().NewPublicKey(pubBytes)
			if err != nil {
				continue
			}
			rawCfg := make([]byte, 4+len(contents))
			binary.BigEndian.PutUint16(rawCfg[0:2], ver)
			binary.BigEndian.PutUint16(rawCfg[2:4], uint16(len(contents)))
			copy(rawCfg[4:], contents)
			// RFC 9230 Section 4.1.1:
			// KeyID = Expand(Extract("", ObliviousDoHConfig), "odoh key id", Nh)
			prk := hkdfExtract(nil, rawCfg)
			keyID := hkdfExpand(prk, []byte("odoh key id"), hpkeNh)
			return &ODoHConfig{
				KEMID:       kemID,
				KDFID:       kdfID,
				AEADID:      aeadID,
				PublicKey:   pubKey,
				RawKeyBytes: pubBytes,
				RawConfig:   rawCfg,
				KeyID:       keyID,
				FetchedAt:   time.Now(),
			}, nil
		}
	}
	return nil, errODoHInvalidConfig
}

// MarshalODoHConfigs serializes a single ODoH public key into the RFC 9230
// ObliviousDoHConfigs wire format (used for testing and custom target pinning).
func MarshalODoHConfigs(pubKey *ecdh.PublicKey) []byte {
	pkBytes := pubKey.Bytes()
	contentsLen := 8 + len(pkBytes)
	cfgLen := 4 + contentsLen
	out := make([]byte, 2+cfgLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(cfgLen))
	binary.BigEndian.PutUint16(out[2:4], odohVersion)
	binary.BigEndian.PutUint16(out[4:6], uint16(contentsLen))
	binary.BigEndian.PutUint16(out[6:8], hpkeKEMX255)
	binary.BigEndian.PutUint16(out[8:10], hpkeKDF256)
	binary.BigEndian.PutUint16(out[10:12], hpkeAEAD128)
	binary.BigEndian.PutUint16(out[12:14], uint16(len(pkBytes)))
	copy(out[14:], pkBytes)
	return out
}

// SealQuery encrypts a raw DNS wire query into an RFC 9230 ObliviousDoHMessage
// (msg_type = 0x01) and returns the wire bytes plus the ODoHClientContext needed
// to open the target's encrypted response.
func (cfg *ODoHConfig) SealQuery(dnsQuery []byte) ([]byte, *ODoHClientContext, error) {
	if cfg == nil || cfg.PublicKey == nil {
		return nil, nil, errODoHInvalidConfig
	}
	// Build ObliviousDoHMessagePlaintext:
	// [2-byte dns_message_len][dns_message][2-byte padding_len][padding]
	// Pad total plaintext to a multiple of 64 bytes with CSPRNG bytes.
	baseLen := 4 + len(dnsQuery)
	padLen := (64 - (baseLen % 64)) % 64
	plaintext := make([]byte, baseLen+padLen)
	binary.BigEndian.PutUint16(plaintext[0:2], uint16(len(dnsQuery)))
	copy(plaintext[2:2+len(dnsQuery)], dnsQuery)
	binary.BigEndian.PutUint16(plaintext[2+len(dnsQuery):4+len(dnsQuery)], uint16(padLen))
	if padLen > 0 {
		GlobalPrivacy.FillCryptoRandom(plaintext[4+len(dnsQuery):])
	}
	// Generate ephemeral X25519 keypair
	skE, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	enc, sharedSecret, err := hpkeEncapX25519(skE, cfg.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	key, baseNonce, exporterSecret := hpkeKeyScheduleBase(sharedSecret, []byte("odoh query"))
	// RFC 9230 Section 4.1.2:
	// aad = 0x01 || uint16(len(KeyID)) || KeyID
	aad := make([]byte, 3+len(cfg.KeyID))
	aad[0] = odohMsgQuery
	binary.BigEndian.PutUint16(aad[1:3], uint16(len(cfg.KeyID)))
	copy(aad[3:], cfg.KeyID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, baseNonce, plaintext, aad)
	// encrypted_message = enc || ct
	encMsgLen := len(enc) + len(ct)
	wire := make([]byte, 3+len(cfg.KeyID)+2+encMsgLen)
	copy(wire[0:3+len(cfg.KeyID)], aad)
	binary.BigEndian.PutUint16(wire[3+len(cfg.KeyID):5+len(cfg.KeyID)], uint16(encMsgLen))
	copy(wire[5+len(cfg.KeyID):], enc)
	copy(wire[5+len(cfg.KeyID)+len(enc):], ct)
	return wire, &ODoHClientContext{
		exporterSecret: exporterSecret,
		queryPlaintext: plaintext,
	}, nil
}

// OpenResponse authenticates and decrypts an RFC 9230 ObliviousDoHMessage
// response (msg_type = 0x02) and returns the inner DNS response wire bytes.
func (cctx *ODoHClientContext) OpenResponse(respWire []byte) ([]byte, error) {
	if len(respWire) < 5 {
		return nil, errODoHMalformedPacket
	}
	if respWire[0] != odohMsgResponse {
		return nil, errODoHResponseType
	}
	nonceLen := int(binary.BigEndian.Uint16(respWire[1:3]))
	if nonceLen < 16 || len(respWire) < 3+nonceLen+2 {
		return nil, errODoHMalformedPacket
	}
	respNonce := respWire[3 : 3+nonceLen]
	encRespLen := int(binary.BigEndian.Uint16(respWire[3+nonceLen : 5+nonceLen]))
	if len(respWire) < 5+nonceLen+encRespLen {
		return nil, errODoHMalformedPacket
	}
	encResp := respWire[5+nonceLen : 5+nonceLen+encRespLen]
	// RFC 9230 Section 4.2:
	// secret = context.Export("odoh response", Nk)
	secret := hpkeExport(cctx.exporterSecret, []byte("odoh response"), hpkeNk)
	// salt = query_plaintext || uint16(len(response_nonce)) || response_nonce
	salt := make([]byte, len(cctx.queryPlaintext)+2+nonceLen)
	copy(salt, cctx.queryPlaintext)
	binary.BigEndian.PutUint16(salt[len(cctx.queryPlaintext):], uint16(nonceLen))
	copy(salt[len(cctx.queryPlaintext)+2:], respNonce)
	prk := hkdfExtract(salt, secret)
	key := hkdfExpand(prk, []byte("odoh key"), hpkeNk)
	nonce := hkdfExpand(prk, []byte("odoh nonce"), hpkeNn)
	// aad = 0x02 || uint16(len(response_nonce)) || response_nonce
	aad := respWire[0 : 3+nonceLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, encResp, aad)
	if err != nil {
		return nil, err
	}
	return unpackODoHPlaintext(plaintext)
}

// OpenQueryAndSealResponse implements the RFC 9230 Target side (used for unit
// testing and self-hosted NetMerge ODoH targets).
func OpenQueryAndSealResponse(
	skR *ecdh.PrivateKey,
	cfg *ODoHConfig,
	queryWire []byte,
	resolverFn func(dnsQuery []byte) ([]byte, error),
) ([]byte, error) {
	if len(queryWire) < 5 {
		return nil, errODoHMalformedPacket
	}
	if queryWire[0] != odohMsgQuery {
		return nil, errODoHResponseType
	}
	keyIDLen := int(binary.BigEndian.Uint16(queryWire[1:3]))
	if len(queryWire) < 3+keyIDLen+2 {
		return nil, errODoHMalformedPacket
	}
	keyID := queryWire[3 : 3+keyIDLen]
	if !bytes.Equal(keyID, cfg.KeyID) {
		return nil, errors.New("odoh: key_id mismatch")
	}
	encMsgLen := int(binary.BigEndian.Uint16(queryWire[3+keyIDLen : 5+keyIDLen]))
	if encMsgLen < 32+16 || len(queryWire) < 5+keyIDLen+encMsgLen {
		return nil, errODoHMalformedPacket
	}
	encMsg := queryWire[5+keyIDLen : 5+keyIDLen+encMsgLen]
	enc := encMsg[:32]
	ct := encMsg[32:]
	sharedSecret, err := hpkeDecapX25519(enc, skR)
	if err != nil {
		return nil, err
	}
	key, baseNonce, exporterSecret := hpkeKeyScheduleBase(sharedSecret, []byte("odoh query"))
	aad := queryWire[:3+keyIDLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	queryPlaintext, err := aead.Open(nil, baseNonce, ct, aad)
	if err != nil {
		return nil, err
	}
	dnsQuery, err := unpackODoHPlaintext(queryPlaintext)
	if err != nil {
		return nil, err
	}
	dnsResp, err := resolverFn(dnsQuery)
	if err != nil {
		return nil, err
	}
	// Build response plaintext
	respPlain := make([]byte, 4+len(dnsResp))
	binary.BigEndian.PutUint16(respPlain[0:2], uint16(len(dnsResp)))
	copy(respPlain[2:2+len(dnsResp)], dnsResp)
	binary.BigEndian.PutUint16(respPlain[2+len(dnsResp):4+len(dnsResp)], 0)
	respNonce := make([]byte, 16)
	GlobalPrivacy.FillCryptoRandom(respNonce)
	secret := hpkeExport(exporterSecret, []byte("odoh response"), hpkeNk)
	salt := make([]byte, len(queryPlaintext)+2+len(respNonce))
	copy(salt, queryPlaintext)
	binary.BigEndian.PutUint16(salt[len(queryPlaintext):], uint16(len(respNonce)))
	copy(salt[len(queryPlaintext)+2:], respNonce)
	prk := hkdfExtract(salt, secret)
	rKey := hkdfExpand(prk, []byte("odoh key"), hpkeNk)
	rNonce := hkdfExpand(prk, []byte("odoh nonce"), hpkeNn)
	respAAD := make([]byte, 3+len(respNonce))
	respAAD[0] = odohMsgResponse
	binary.BigEndian.PutUint16(respAAD[1:3], uint16(len(respNonce)))
	copy(respAAD[3:], respNonce)
	rBlock, err := aes.NewCipher(rKey)
	if err != nil {
		return nil, err
	}
	rAEAD, err := cipher.NewGCM(rBlock)
	if err != nil {
		return nil, err
	}
	encResp := rAEAD.Seal(nil, rNonce, respPlain, respAAD)
	out := make([]byte, len(respAAD)+2+len(encResp))
	copy(out, respAAD)
	binary.BigEndian.PutUint16(out[len(respAAD):len(respAAD)+2], uint16(len(encResp)))
	copy(out[len(respAAD)+2:], encResp)
	return out, nil
}

func unpackODoHPlaintext(pt []byte) ([]byte, error) {
	if len(pt) < 4 {
		return nil, errODoHMalformedPacket
	}
	dnsLen := int(binary.BigEndian.Uint16(pt[0:2]))
	if len(pt) < 2+dnsLen+2 {
		return nil, errODoHMalformedPacket
	}
	padLen := int(binary.BigEndian.Uint16(pt[2+dnsLen : 4+dnsLen]))
	if len(pt) != 4+dnsLen+padLen {
		return nil, errODoHMalformedPacket
	}
	return pt[2 : 2+dnsLen], nil
}

// ---- RFC 9180 HPKE Primitives (DHKEM-X25519-HKDF-SHA256 / AES-128-GCM) ----

var (
	kemSuiteID  = []byte{'K', 'E', 'M', 0x00, 0x20}
	hpkeSuiteID = []byte{'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01}
)

func hpkeEncapX25519(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey) (enc, sharedSecret []byte, err error) {
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc = skE.PublicKey().Bytes()
	pkRm := pkR.Bytes()
	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	eaePRK := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	sharedSecret = labeledExpand(kemSuiteID, eaePRK, "shared_secret", kemContext, hpkeNh)
	return enc, sharedSecret, nil
}

func hpkeDecapX25519(enc []byte, skR *ecdh.PrivateKey) ([]byte, error) {
	pkE, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, err
	}
	pkRm := skR.PublicKey().Bytes()
	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	eaePRK := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	return labeledExpand(kemSuiteID, eaePRK, "shared_secret", kemContext, hpkeNh), nil
}

func hpkeKeyScheduleBase(sharedSecret, info []byte) (key, baseNonce, exporterSecret []byte) {
	pskIDHash := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(hpkeSuiteID, nil, "info_hash", info)
	ksContext := make([]byte, 1+len(pskIDHash)+len(infoHash))
	ksContext[0] = 0x00 // mode_base
	copy(ksContext[1:], pskIDHash)
	copy(ksContext[1+len(pskIDHash):], infoHash)
	secret := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	key = labeledExpand(hpkeSuiteID, secret, "key", ksContext, hpkeNk)
	baseNonce = labeledExpand(hpkeSuiteID, secret, "base_nonce", ksContext, hpkeNn)
	exporterSecret = labeledExpand(hpkeSuiteID, secret, "exp", ksContext, hpkeNh)
	return key, baseNonce, exporterSecret
}

func hpkeExport(exporterSecret, exporterContext []byte, length int) []byte {
	return labeledExpand(hpkeSuiteID, exporterSecret, "sec", exporterContext, length)
}

func labeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	labeledIKM := make([]byte, 0, 7+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, "HPKE-v1"...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdfExtract(salt, labeledIKM)
}

func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) []byte {
	labeledInfo := make([]byte, 2, 2+7+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], uint16(length))
	labeledInfo = append(labeledInfo, "HPKE-v1"...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdfExpand(prk, labeledInfo, length)
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, hpkeNh)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out []byte
	var prev []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

// ---- ODoHEngine: Target Config Caching & Oblivious Relay Dispatch ----

type ODoHEngine struct {
	mu         sync.RWMutex
	targetCfg  *ODoHConfig
	proxyURL   string
	targetHost string
	targetPath string
	refreshing atomic.Bool
}

var GlobalODoH = &ODoHEngine{
	targetHost: "odoh.cloudflare-dns.com",
	targetPath: "/dns-query",
}

// ConfigureODoH sets a custom ODoH Proxy URL (e.g. "https://odoh-relay.example/proxy")
// and optional pre-fetched ODoHConfig. Even when proxyURL is empty, ODoHEngine
// can send HPKE-encrypted ODoH queries directly to https://odoh.cloudflare-dns.com/dns-query
// (or through the link's PrivacyEndpoint tunnel) so DNS payloads are HPKE-encrypted.
func (o *ODoHEngine) ConfigureODoH(proxyURL, targetHost, targetPath string, cfg *ODoHConfig) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if proxyURL != "" {
		o.proxyURL = proxyURL
	}
	if targetHost != "" {
		o.targetHost = targetHost
	}
	if targetPath != "" {
		o.targetPath = targetPath
	}
	if cfg != nil {
		o.targetCfg = cfg
	}
}

func (o *ODoHEngine) GetTargetConfig(r *VIPResolver, link LinkType) *ODoHConfig {
	o.mu.RLock()
	cfg := o.targetCfg
	o.mu.RUnlock()
	if cfg != nil && time.Since(cfg.FetchedAt) < 6*time.Hour {
		return cfg
	}
	if o.refreshing.CompareAndSwap(false, true) {
		go func() {
			defer o.refreshing.Store(false)
			o.refreshTargetConfig(r, link)
		}()
	}
	return cfg
}

func (o *ODoHEngine) refreshTargetConfig(r *VIPResolver, link LinkType) {
	if r == nil {
		return
	}
	client := r.dohClients[dohClientKey(link, "https://1.1.1.1/dns-query")]
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/.well-known/odohconfigs", nil)
	if err != nil {
		return
	}
	req.Host = "odoh.cloudflare-dns.com"
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return
	}
	if parsed, err := ParseODoHConfigs(raw); err == nil && parsed != nil {
		o.mu.Lock()
		o.targetCfg = parsed
		o.mu.Unlock()
	}
}
