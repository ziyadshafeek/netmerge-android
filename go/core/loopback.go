package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netmerge/core/multipath"
)

// startLoopbackServer starts the 127.0.0.1:18080 HTTP server for on-phone
// HTTPS compounding. Any https:// URL sent to
// http://127.0.0.1:18080/compound?url=https://... is downloaded via the
// HalvingSplicer across Wi-Fi + Cellular, using the system's TLS roots
// (no custom CA, no MITM, no banking breakage).
func (e *Engine) startLoopbackServer() {
	if e.mpEngine == nil {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/compound", e.handleCompoundHTTPS)
	srv := &http.Server{
		Addr:              "127.0.0.1:18080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		// Don't fail engine startup if loopback can't bind (e.g., in tests).
		_ = srv.ListenAndServe()
	}()
	e.loopbackSrv = srv
}

func (e *Engine) handleCompoundHTTPS(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "missing url parameter", http.StatusBadRequest)
		return
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		http.Error(w, "invalid target url", http.StatusBadRequest)
		return
	}
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	ctx := r.Context()
	_, dualEP := e.mpEngine.Resolver.GetOrAllocate(ctx, host)
	if dualEP == nil {
		dualEP = &multipath.DualEndpoint{Domain: host, WiFiAddr: host, CellAddr: host}
	}
	wifiIP, cellIP := dualEP.WaitReady(ctx)
	probeIP := wifiIP
	probeLink := multipath.LinkWiFi
	if probeIP == "" {
		probeIP = cellIP
		probeLink = multipath.LinkCellular
	}
	if probeIP == "" {
		// Fail closed: never fall back to dialing a raw hostname (would
		// resolve via system DNS and leak).
		http.Error(w, "no upstream address for host", http.StatusBadGateway)
		return
	}

	// SNI-preserving HTTPS clients pinned to each physical radio. Dialling
	// the resolved IP directly (with ServerName=host) keeps DNS private.
	makeHTTPSClient := func(link multipath.LinkType, sniHost string) *http.Client {
		dialer := multipath.NewBoundDialer(e.mpEngine.Binder, link, 8*time.Second)
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
					return multipath.DialBoundContext(dctx, dialer, network, addr)
				},
				ForceAttemptHTTP2:     false, // HTTP/1.1: independent TCP sockets per worker
				MaxIdleConnsPerHost:   6,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 8 * time.Second,
				TLSClientConfig: &tls.Config{
					ServerName: sniHost,
					MinVersion: tls.VersionTLS12,
				},
			},
		}
	}
	splicer := &multipath.HalvingSplicer{
		WiFiClient: makeHTTPSClient(multipath.LinkWiFi, host),
		CellClient: makeHTTPSClient(multipath.LinkCellular, host),
	}

	// Probe byte 0 to discover total size and ETag via Content-Range.
	probeCtx, cancelProbe := context.WithTimeout(ctx, 8*time.Second)
	defer cancelProbe()
	probeURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, net.JoinHostPort(probeIP, port), parsedURL.RequestURI())
	probeReq, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	probeReq.Host = host
	for k, vv := range r.Header {
		if !strings.EqualFold(k, "Host") {
			probeReq.Header[k] = vv
		}
	}
	var initialOffset int64
	if clientRange := r.Header.Get("Range"); strings.HasPrefix(clientRange, "bytes=") {
		parts := strings.SplitN(strings.TrimPrefix(clientRange, "bytes="), "-", 2)
		if len(parts) >= 1 {
			initialOffset, _ = strconv.ParseInt(parts[0], 10, 64)
		}
	}
	probeReq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", initialOffset, initialOffset))
	probeClient := splicer.WiFiClient
	if probeLink == multipath.LinkCellular {
		probeClient = splicer.CellClient
	}
	probeResp, err := probeClient.Do(probeReq)
	if err != nil {
		http.Error(w, "probe failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	_, _ = io.CopyN(io.Discard, probeResp.Body, 1)
	_ = probeResp.Body.Close()
	totalSize := parseTotalSizeFromContentRange(probeResp.Header.Get("Content-Range"))
	etag := probeResp.Header.Get("ETag")

	// No Range support: fall back to direct streaming.
	if probeResp.StatusCode != http.StatusPartialContent || totalSize <= 0 {
		directReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		directReq.Host = host
		resp, derr := probeClient.Do(directReq)
		if derr != nil {
			http.Error(w, derr.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	for k, vv := range probeResp.Header {
		if !strings.EqualFold(k, "Content-Range") && !strings.EqualFold(k, "Content-Length") {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.Header().Set("Content-Length", strconv.FormatInt(totalSize-initialOffset, 10))
	if initialOffset > 0 {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", initialOffset, totalSize-1, totalSize))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	origReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	origReq.Host = host
	if parsedURL.Scheme == "https" {
		origReq.TLS = &tls.ConnectionState{ServerName: host}
	}
	_ = splicer.StreamWithDynamicHalving(ctx, w, origReq, dualEP, port, etag, initialOffset, totalSize)
}

// parseTotalSizeFromContentRange parses "bytes 0-262143/104857600" -> 104857600.
func parseTotalSizeFromContentRange(cr string) int64 {
	if len(cr) < 7 || cr[:6] != "bytes " {
		return -1
	}
	slash := strings.LastIndexByte(cr, '/')
	if slash == -1 || slash+1 >= len(cr) {
		return -1
	}
	totalStr := cr[slash+1:]
	if totalStr == "*" {
		return -1
	}
	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil {
		return -1
	}
	return total
}

var _ = fmt.Sprintf // keep fmt imported if unused
