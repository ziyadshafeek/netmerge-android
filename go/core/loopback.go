package core

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"netmerge/core/multipath"
)

// startLoopbackServer starts the 127.0.0.1:18080 HTTP server for on-phone
// HTTPS compounding. Any https:// URL sent to
// http://127.0.0.1:18080/compound?url=https://... is downloaded via the
// HalvingSplicer across Wi-Fi + Cellular, using the system's TLS roots
// (no custom CA, no banking breakage).
func (e *Engine) startLoopbackServer() {
	if e.mpEngine == nil {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/compound", func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			http.Error(w, "missing url parameter", http.StatusBadRequest)
			return
		}

		// Use the splicer to compound the download
		// For now, this is a placeholder - the full implementation
		// requires the HalvingSplicer.StreamWithDynamicHalving API
		http.Error(w, "compounding not yet implemented for this endpoint", http.StatusNotImplemented)
	})

	srv := &http.Server{
		Addr:              "127.0.0.1:18080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		// Don't fail engine startup if loopback can't bind (e.g., in tests)
		_ = srv.ListenAndServe()
	}()

	// Store for shutdown
	e.loopbackSrv = srv
}

// parseTotalSizeFromContentRange parses "bytes 0-262143/104857600" -> 104857600
func parseTotalSizeFromContentRange(cr string) int64 {
	if len(cr) < 7 || cr[:6] != "bytes " {
		return -1
	}
	slash := -1
	for i := len(cr) - 1; i >= 0; i-- {
		if cr[i] == '/' {
			slash = i
			break
		}
	}
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
var _ = multipath.LinkWiFi
