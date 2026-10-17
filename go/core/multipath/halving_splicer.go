// Package multipath implements NetMerge's zero-VPS compounding engine.
//
// A single client stream (one TCP connection as seen by the app) is
// transparently split into parallel HTTP byte-range requests across Wi-Fi
// and cellular. Workers pull byte ranges concurrently; an in-flight
// work-stealing bisection lets a fast link steal the tail of a slow link's
// segment. Completed ranges are written to the client in strict order.
//
// Memory is bounded: at most one SuperWindowSize (16MB) buffer is live at
// any time, and each super-window is flushed to the client before the next
// begins.
package multipath

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// SuperWindowSize bounds in-RAM buffering. One super-window is
	// downloaded at a time, then flushed in order to the client.
	SuperWindowSize int64 = 16 * 1024 * 1024
	// MinBisectBytes is the minimum remaining bytes that justifies
	// splitting an in-flight segment between two workers.
	MinBisectBytes int64 = 1024 * 1024
	// ReadSliceSize is the per-read granularity when streaming a segment.
	ReadSliceSize int = 32 * 1024
	// maxSegmentFails aborts the download after this many consecutive
	// failures on one segment, so a dead server can't spin forever.
	maxSegmentFails = 8
	// retryBackoff is the pause between segment retries.
	retryBackoff = 40 * time.Millisecond
)

// errETagMismatch is returned by streamSegment when the server answers a
// Range request with 200 OK instead of 206 Partial Content while an
// If-Range ETag was sent. It means this CDN edge has a different version
// of the object; the caller should retry against the other edge.
var errETagMismatch = errors.New("cdn etag mismatch")

// dynamicSegment is one byte range within a super-window. Offsets are
// relative to the super-window base. All mutable fields are guarded by the
// downloadSuperWindow mutex.
type dynamicSegment struct {
	start    int64 // immutable start offset within the window
	writePos int64 // next offset to fill (moves as bytes arrive)
	end      int64 // inclusive end offset; may shrink via in-flight bisection
	inProg   bool
	done     bool
	fails    int
	cancel   context.CancelFunc
}

// HalvingSplicer downloads a resource via parallel HTTP range requests on
// Wi-Fi and cellular and emits a single ordered byte stream.
type HalvingSplicer struct {
	WiFiClient *http.Client
	CellClient *http.Client
}

// NewHalvingSplicer builds a splicer whose upstream sockets are dialed
// through the given binder (interface pinning + VPN protection).
func NewHalvingSplicer(binder SocketBinder) *HalvingSplicer {
	makeClient := func(link LinkType) *http.Client {
		dialer := NewBoundDialer(binder, link, 8*time.Second)
		return &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     false, // HTTP/1.1: raw bytes, no multiplexing overhead
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 6 * time.Second,
				ReadBufferSize:        64 * 1024,
			},
		}
	}
	return &HalvingSplicer{
		WiFiClient: makeClient(LinkWiFi),
		CellClient: makeClient(LinkCellular),
	}
}

// StreamWithDynamicHalving downloads [initialOffset, totalSize) and writes
// the bytes in strict order to clientWriter. The resource is fetched in
// SuperWindowSize chunks so RAM stays bounded regardless of total size.
//
// origReq is the client's original request (URL, Host, headers, TLS state
// are reused for the upstream range requests). ep holds the per-link CDN
// endpoints; port is the origin port ("80"/"443"). etag, when non-empty,
// is sent as If-Range on every range request for CDN-edge consistency.
func (hs *HalvingSplicer) StreamWithDynamicHalving(
	ctx context.Context,
	clientWriter io.Writer,
	origReq *http.Request,
	ep *DualEndpoint,
	port string,
	etag string,
	initialOffset int64,
	totalSize int64,
) error {
	if totalSize <= 0 {
		return fmt.Errorf("multipath: invalid total size %d", totalSize)
	}
	if initialOffset < 0 {
		initialOffset = 0
	}
	if initialOffset >= totalSize {
		return nil // nothing to fetch
	}
	if ep == nil {
		return errors.New("multipath: nil dual endpoint")
	}

	ctx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	// One reusable super-window buffer for the whole stream.
	windowBuf := make([]byte, SuperWindowSize)
	// forceSameEdge flips when the cellular CDN edge disagrees on ETag;
	// cellular then dials the Wi-Fi edge IP over the cellular interface.
	var forceSameEdge atomic.Bool

	for winBase := initialOffset; winBase < totalSize; winBase += SuperWindowSize {
		winLen := totalSize - winBase
		if winLen > SuperWindowSize {
			winLen = SuperWindowSize
		}
		if err := hs.downloadSuperWindow(ctx, windowBuf[:winLen], winBase, winLen,
			origReq, ep, port, etag, &forceSameEdge); err != nil {
			return err
		}
		if _, err := clientWriter.Write(windowBuf[:winLen]); err != nil {
			cancelAll()
			return fmt.Errorf("multipath: client write failed: %w", err)
		}
	}
	return nil
}

// downloadSuperWindow fetches one super-window [winBase, winBase+winLen)
// into winBuf using parallel workers with in-flight work stealing.
func (hs *HalvingSplicer) downloadSuperWindow(
	ctx context.Context,
	winBuf []byte,
	winBase int64,
	winLen int64,
	origReq *http.Request,
	ep *DualEndpoint,
	port string,
	etag string,
	forceSameEdge *atomic.Bool,
) error {
	ctx, cancelWin := context.WithCancel(ctx)
	defer cancelWin()

	var mu sync.Mutex
	cond := sync.NewCond(&mu)

	// Start with two halves (one per link); tiny windows stay whole.
	mid := winLen / 2
	var segments []*dynamicSegment
	if mid >= MinBisectBytes {
		segments = []*dynamicSegment{
			{start: 0, end: mid - 1},
			{start: mid, end: winLen - 1},
		}
	} else {
		segments = []*dynamicSegment{{start: 0, end: winLen - 1}}
	}

	var fatalErr error
	allDone := func() bool {
		for _, s := range segments {
			if !s.done {
				return false
			}
		}
		return true
	}
	fail := func(format string, args ...any) {
		if fatalErr == nil {
			fatalErr = fmt.Errorf(format, args...)
		}
		cond.Broadcast()
	}

	// acquireSegment hands out an unstarted segment, or bisects the
	// in-progress segment with the most remaining bytes (in-flight work
	// stealing). Returns nil when there is nothing left to do.
	acquireSegment := func() (*dynamicSegment, context.Context) {
		mu.Lock()
		defer mu.Unlock()
		for {
			if ctx.Err() != nil || fatalErr != nil || allDone() {
				return nil, nil
			}
			for _, s := range segments {
				if !s.done && !s.inProg {
					s.inProg = true
					sCtx, sCancel := context.WithCancel(ctx)
					s.cancel = sCancel
					return s, sCtx
				}
			}
			// In-flight bisection: split the largest remaining segment.
			var largest *dynamicSegment
			var maxRem int64
			for _, s := range segments {
				if !s.done && s.inProg {
					if rem := s.end - s.writePos + 1; rem > maxRem {
						maxRem, largest = rem, s
					}
				}
			}
			if largest != nil && maxRem >= 2*MinBisectBytes {
				splitAt := largest.writePos + maxRem/2
				oldEnd := largest.end
				largest.end = splitAt - 1
				sCtx, sCancel := context.WithCancel(ctx)
				ns := &dynamicSegment{
					start:    splitAt,
					writePos: splitAt,
					end:      oldEnd,
					inProg:   true,
					cancel:   sCancel,
				}
				segments = append(segments, ns)
				return ns, sCtx
			}
			cond.Wait()
		}
	}

	worker := func(link LinkType) {
		client := hs.WiFiClient
		if link == LinkCellular {
			client = hs.CellClient
		}
		scratch := make([]byte, ReadSliceSize)

		for {
			seg, segCtx := acquireSegment()
			if seg == nil {
				return
			}
			// Pick the target: cellular normally uses its native edge;
			// after an ETag mismatch it falls back to the Wi-Fi edge IP
			// (still dialed over the cellular interface, so radio
			// bandwidth still compounds).
			targetIP := ep.WiFiAddr
			if link == LinkCellular && !forceSameEdge.Load() && ep.CellAddr != "" {
				targetIP = ep.CellAddr
			}
			if targetIP == "" {
				targetIP = ep.WiFiAddr
			}
			if targetIP == "" {
				mu.Lock()
				fail("multipath: no target IP for link %d", int(link))
				mu.Unlock()
				return
			}

			mu.Lock()
			reqStart, reqEnd := winBase+seg.writePos, winBase+seg.end
			mu.Unlock()

			err := hs.streamSegment(segCtx, client, origReq, targetIP, port,
				etag, reqStart, reqEnd, scratch,
				func(chunk []byte) (bool, error) {
					mu.Lock()
					defer mu.Unlock()
					if seg.done {
						return false, nil
					}
					// The segment may have been bisected while we were
					// reading; never write past the (possibly shrunk) end.
					allow := seg.end - seg.writePos + 1
					if allow <= 0 {
						return false, nil
					}
					n := int64(len(chunk))
					if n > allow {
						n = allow
					}
					copy(winBuf[seg.writePos:seg.writePos+n], chunk[:n])
					seg.writePos += n
					if seg.writePos > seg.end {
						seg.done = true
						if seg.cancel != nil {
							seg.cancel()
						}
						cond.Broadcast()
						return false, nil
					}
					return true, nil
				})

			mu.Lock()
			switch {
			case seg.done:
				// Finished (possibly by a racing bisect worker); nothing to do.
			case errors.Is(err, errETagMismatch) && link == LinkCellular:
				// Cellular CDN edge disagrees; retry it against the Wi-Fi edge.
				forceSameEdge.Store(true)
				seg.inProg = false
				seg.fails = 0
			case err != nil && !errors.Is(err, context.Canceled):
				seg.fails++
				if seg.fails >= maxSegmentFails {
					fail("multipath: segment [%d-%d] failed %d times: %v",
						reqStart, reqEnd, seg.fails, err)
				} else {
					seg.inProg = false
				}
			case err != nil:
				// Context canceled (bisection/done): just re-acquire.
				seg.inProg = false
			default:
				seg.inProg = false
			}
			cond.Broadcast()
			mu.Unlock()

			if err != nil && !seg.done && !errors.Is(err, context.Canceled) &&
				!errors.Is(err, errETagMismatch) {
				select {
				case <-ctx.Done():
				case <-time.After(retryBackoff):
				}
			}
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ { // 2 workers per link
		wg.Add(2)
		go func() { defer wg.Done(); worker(LinkWiFi) }()
		go func() { defer wg.Done(); worker(LinkCellular) }()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if fatalErr != nil {
		return fatalErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// streamSegment performs one HTTP Range GET and feeds the body to onBytes
// in ReadSliceSize slices. onBytes returns false when the caller should
// stop reading (segment complete or bisected away). An If-Range header is
// sent when etag is non-empty; a 200 OK answer to a ranged request then
// means the edge disagrees on the object version (errETagMismatch).
func (hs *HalvingSplicer) streamSegment(
	ctx context.Context,
	client *http.Client,
	origReq *http.Request,
	targetIP, port, etag string,
	absStart, absEnd int64,
	scratch []byte,
	onBytes func([]byte) (bool, error),
) error {
	scheme := "http"
	if origReq.TLS != nil {
		scheme = "https"
	}
	urlStr := fmt.Sprintf("%s://%s%s",
		scheme, net.JoinHostPort(targetIP, port), origReq.URL.RequestURI())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}
	req.Host = origReq.Host
	for k, v := range origReq.Header {
		req.Header[k] = v
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", absStart, absEnd))
	if etag != "" {
		req.Header.Set("If-Range", etag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent:
		// expected
	case http.StatusOK:
		// Server ignored the Range request. With an ETag this signals a
		// version mismatch on this edge; without one, ranges aren't
		// supported at all and splicing can't proceed.
		if etag != "" {
			return errETagMismatch
		}
		return fmt.Errorf("multipath: server does not support range requests (200 OK)")
	default:
		return fmt.Errorf("multipath: unexpected status %d for range %d-%d",
			resp.StatusCode, absStart, absEnd)
	}

	for {
		n, rerr := resp.Body.Read(scratch)
		if n > 0 {
			keep, cerr := onBytes(scratch[:n])
			if cerr != nil {
				return cerr
			}
			if !keep {
				return nil
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}
