package multipath

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubBinder approves every bind; the dialer it feeds is a plain one, so
// test traffic flows over loopback.
type stubBinder struct{}

func (stubBinder) BindAndProtect(fd int64, networkType int) bool   { return true }
func (stubBinder) CanBindLink(networkType int) bool                { return true }
func (stubBinder) OnBytes(networkType int, rxBytes, txBytes int64) {}

// rangeHandler serves data with HTTP Range + ETag support. If ifRangeFail
// is true it answers 200 OK (full body) whenever If-Range doesn't match
// its ETag, simulating an out-of-sync CDN edge.
func rangeHandler(data []byte, etag string, ifRangeFail bool, hits *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		rh := r.Header.Get("Range")
		if rh == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			return
		}
		var start, end int64
		if _, err := fmt.Sscanf(rh, "bytes=%d-%d", &start, &end); err != nil ||
			start < 0 || end >= int64(len(data)) || start > end {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if ir := r.Header.Get("If-Range"); ir != "" && ir != etag {
			if ifRangeFail {
				// Edge disagrees on version: 200 with full body.
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.WriteHeader(http.StatusOK)
				w.Write(data)
				return
			}
			// Otherwise ignore If-Range and serve the range anyway.
		}
		w.Header().Set("Content-Range",
			fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data[start : end+1])
	})
}

// serverOn starts an httptest server bound to ip on the same port as
// refPort, so Wi-Fi and cellular endpoints can share one port value.
func serverOn(t *testing.T, ip string, refPort int, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	l, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(refPort)))
	if err != nil {
		t.Fatalf("listen %s: %v", ip, err)
	}
	s.Listener = l
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func srvPort(t *testing.T, s *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func testData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func testRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://example.com/file", nil)
}

func TestStreamSplicedDownload(t *testing.T) {
	const size = 20 * 1024 * 1024 // > SuperWindowSize: exercises multi-window
	data := testData(t, size)

	var wifiHits, cellHits atomic.Int64
	wifiSrv := httptest.NewServer(rangeHandler(data, `"v1"`, false, &wifiHits))
	defer wifiSrv.Close()
	port := srvPort(t, wifiSrv)
	// Cellular edge on a different loopback IP, same port.
	cellSrv := serverOn(t, "127.0.0.2", mustPort(t, port),
		rangeHandler(data, `"v1"`, false, &cellHits))
	defer cellSrv.Close()

	hs := NewHalvingSplicer(stubBinder{})
	ep := &DualEndpoint{Domain: "example.com", WiFiAddr: "127.0.0.1", CellAddr: "127.0.0.2"}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := hs.StreamWithDynamicHalving(ctx, &out, testRequest(), ep, port, `"v1"`, 0, int64(len(data)))
	if err != nil {
		t.Fatalf("StreamWithDynamicHalving: %v", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("spliced output differs: got %d bytes, want %d", out.Len(), len(data))
	}
	t.Logf("wifi hits=%d cell hits=%d", wifiHits.Load(), cellHits.Load())
	if wifiHits.Load() == 0 || cellHits.Load() == 0 {
		t.Fatalf("expected both links to serve ranges (wifi=%d cell=%d)",
			wifiHits.Load(), cellHits.Load())
	}
}

func TestStreamSmallFile(t *testing.T) {
	data := testData(t, 100*1024) // < MinBisectBytes: single segment
	srv := httptest.NewServer(rangeHandler(data, `"v1"`, false, nil))
	defer srv.Close()
	port := srvPort(t, srv)

	hs := NewHalvingSplicer(stubBinder{})
	ep := &DualEndpoint{WiFiAddr: "127.0.0.1", CellAddr: "127.0.0.1"}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := hs.StreamWithDynamicHalving(ctx, &out, testRequest(), ep, port, `"v1"`, 0, int64(len(data))); err != nil {
		t.Fatalf("small file: %v", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("small file mismatch: got %d want %d", out.Len(), len(data))
	}
}

func TestStreamETagMismatchFallback(t *testing.T) {
	const size = 4 * 1024 * 1024
	data := testData(t, size)

	var wifiHits, cellHits atomic.Int64
	wifiSrv := httptest.NewServer(rangeHandler(data, `"wifi-v1"`, false, &wifiHits))
	defer wifiSrv.Close()
	port := srvPort(t, wifiSrv)
	// Cellular edge serves the same bytes but a different ETag, so every
	// If-Range request from cellular gets 200 OK (mismatch).
	serverOn(t, "127.0.0.2", mustPort(t, port),
		rangeHandler(data, `"cell-v9"`, true, &cellHits))

	hs := NewHalvingSplicer(stubBinder{})
	ep := &DualEndpoint{Domain: "example.com", WiFiAddr: "127.0.0.1", CellAddr: "127.0.0.2"}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	// ETag presented is the Wi-Fi edge's; cellular will disagree.
	err := hs.StreamWithDynamicHalving(ctx, &out, testRequest(), ep, port, `"wifi-v1"`, 0, int64(len(data)))
	if err != nil {
		t.Fatalf("etag fallback: %v", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("etag fallback output mismatch: got %d want %d", out.Len(), len(data))
	}
	t.Logf("after fallback: wifi hits=%d cell hits=%d", wifiHits.Load(), cellHits.Load())
	if cellHits.Load() == 0 {
		t.Fatalf("expected cellular edge to be tried before fallback")
	}
}

func TestStreamNoRangeSupportFails(t *testing.T) {
	data := testData(t, 1024)
	// Server ignores Range entirely (always 200).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	hs := NewHalvingSplicer(stubBinder{})
	ep := &DualEndpoint{WiFiAddr: "127.0.0.1"}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	// No etag: a 200 to a ranged request is a hard error, not a fallback.
	err := hs.StreamWithDynamicHalving(ctx, &out, testRequest(), ep, port, "", 0, int64(len(data)))
	if err == nil {
		t.Fatalf("expected error for range-less server, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestStreamSegmentETagMismatch(t *testing.T) {
	data := testData(t, 64*1024)
	var hits atomic.Int64
	srv := httptest.NewServer(rangeHandler(data, `"srv-etag"`, true, &hits))
	defer srv.Close()
	port := srvPort(t, srv)

	hs := NewHalvingSplicer(stubBinder{})
	req := testRequest()
	scratch := make([]byte, ReadSliceSize)

	// Wrong etag -> errETagMismatch.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := hs.streamSegment(ctx, hs.WiFiClient, req, "127.0.0.1", port,
		`"wrong-etag"`, 0, 1023, scratch, func([]byte) (bool, error) {
			return true, nil
		})
	if !strings.Contains(err.Error(), "etag mismatch") {
		t.Fatalf("expected etag mismatch, got: %v", err)
	}

	// Right etag -> bytes flow.
	var got []byte
	err = hs.streamSegment(ctx, hs.WiFiClient, req, "127.0.0.1", port,
		`"srv-etag"`, 0, 1023, scratch, func(c []byte) (bool, error) {
			got = append(got, c...)
			return true, nil
		})
	if err != nil {
		t.Fatalf("range fetch: %v", err)
	}
	if !bytes.Equal(got, data[:1024]) {
		t.Fatalf("range bytes mismatch")
	}
}

func mustPort(t *testing.T, p string) int {
	t.Helper()
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
