// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MinCompoundSize is the minimum file size for range-based compounding.
// Files smaller than this are streamed directly on the best link.
const MinCompoundSize int64 = 512 * 1024

// relayBufPool provides 128KB buffers for the TLS relay path. Wrapping
// net.Conn in byteCounterWriter masks io.ReaderFrom/io.WriterTo, which would
// otherwise drop io.Copy to a 32KB buffer; CopyBuffer with 128KB keeps
// high-BDP dual-radio streams saturated.
var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 128*1024)
		return &b
	},
}

// byteCounterWriter wraps an io.Writer to report bytes in real-time via the
// binder and feed per-link EWMA goodput samples for the deficit scheduler.
type byteCounterWriter struct {
	w         io.Writer
	binder    SocketBinder
	link      LinkType
	isUpload  bool
	startTime time.Time
	total     int64
}

func (bw *byteCounterWriter) Write(p []byte) (int, error) {
	if bw.startTime.IsZero() {
		bw.startTime = time.Now()
	}
	n, err := bw.w.Write(p)
	if n > 0 {
		bw.total += int64(n)
		if bw.binder != nil {
			if bw.isUpload {
				bw.binder.OnBytes(int(bw.link), 0, int64(n))
			} else {
				bw.binder.OnBytes(int(bw.link), int64(n), 0)
			}
		}
		if bw.total >= 64*1024 {
			RecordLinkGoodput(bw.link, bw.total, time.Since(bw.startTime))
		}
	}
	return n, err
}

// HandleGVisorTCPStream is called for every TCP connection from the app.
// It reads the full initial payload (up to 8KB) to determine the protocol:
//
//   - TLS/encrypted (0x16, banking, UPI, SSH): uses ForwardWithMidHandshakeReplay
//     for dual-link SYN racing with ClientHello replay failover. Zero TLS
//     modification, zero Root CA.
//   - HTTP GET: uses the HalvingSplicer for range-based compounding across
//     both links if the file is >= 512KB and supports ranges.
//   - Other: passes through on the best link.
func (e *OnPhoneCompoundEngine) HandleGVisorTCPStream(
	ctx context.Context,
	clientConn net.Conn,
	ep *DualEndpoint,
	dstPort uint16,
) error {
	defer clientConn.Close()
	portStr := strconv.Itoa(int(dstPort))

	// Read the full initial client payload (up to 8KB) in one shot, NOT 8 bytes!
	// The old 8-byte peek + io.MultiReader caused ForwardWithMidHandshakeReplay
	// to send only 8 bytes of the TLS ClientHello upstream, killing every HTTPS
	// connection. We now read the complete first chunk here.
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	firstChunk := make([]byte, 8192)
	n, _ := clientConn.Read(firstChunk)
	// If it's a TLS ClientHello (0x16), ensure we have the complete TLS record
	if n >= 5 && firstChunk[0] == 0x16 {
		recLen := 5 + (int(firstChunk[3])<<8 | int(firstChunk[4]))
		if recLen > n && recLen <= len(firstChunk) {
			extra, _ := io.ReadFull(clientConn, firstChunk[n:recLen])
			n += extra
		}
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	// If NOT a plain HTTP GET, forward with dual-link striping & handshake failover
	if n < 4 || string(firstChunk[:4]) != "GET " {
		return e.ForwardWithMidHandshakeReplay(ctx, clientConn, firstChunk[:n], ep, portStr)
	}

	// Plain HTTP GET: wrap full stream for HTTP parser
	replayedReader := io.MultiReader(bytes.NewReader(firstChunk[:n]), clientConn)
	bufReader := bufio.NewReader(replayedReader)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return err
	}

	// Explicit Range request (video players, download managers, chunked
	// fetchers): compound it with work-stealing if the span is >= 256KB.
	// The old code passed these straight through, bypassing compounding.
	if rangeHdr := req.Header.Get("Range"); rangeHdr != "" {
		if rs, re, ok := parseRangeHeader(rangeHdr); ok {
			span := re - rs + 1
			if re < 0 || span >= spliceSegmentSize {
				// Open-ended or large: work-steal across both links.
				return e.compoundRange(ctx, clientConn, req, ep, portStr, rs, re)
			}
		}
		return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
	}

	// Probe for range support and file size
	return e.compoundHTTPStream(ctx, clientConn, req, ep, portStr)
}

// parseRangeHeader parses "bytes=start-end" -> (start, end).
// end is -1 for open-ended ("bytes=start-").
func parseRangeHeader(h string) (start, end int64, ok bool) {
	if !strings.HasPrefix(h, "bytes=") {
		return 0, 0, false
	}
	rest := strings.TrimPrefix(h, "bytes=")
	// Only handle single-range "start-end"; ignore suffix ranges ("-500").
	dash := strings.Index(rest, "-")
	if dash <= 0 {
		return 0, 0, false
	}
	s, err := strconv.ParseInt(rest[:dash], 10, 64)
	if err != nil || s < 0 {
		return 0, 0, false
	}
	if dash+1 >= len(rest) {
		return s, -1, true // open-ended
	}
	e, err := strconv.ParseInt(rest[dash+1:], 10, 64)
	if err != nil || e < s {
		return 0, 0, false
	}
	return s, e, true
}

// spliceSegmentSize is the work-stealing micro-chunk size. 256KB amortizes
// HTTP overhead while letting a 4x faster link pull 4x more chunks.
const spliceSegmentSize = 256 * 1024

// spliceMaxInflight caps in-flight segments (8 x 256KB = 2MB RAM ceiling).
const spliceMaxInflight = 8

// compoundRange compounds an explicit client Range request [reqStart, reqEnd]
// across Wi-Fi and Cellular with dynamic work-stealing. reqEnd == -1 means
// open-ended ("bytes=N-"); total size is probed in that case.
func (e *OnPhoneCompoundEngine) compoundRange(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
	ep *DualEndpoint,
	portStr string,
	reqStart, reqEnd int64,
) error {
	// Resolve open-ended range via a probe.
	totalSize := reqEnd + 1 // -1 -> 0 (unknown)
	if reqEnd < 0 {
		probeLink := e.Scheduler.PickOptimalLink(spliceSegmentSize)
		targetIP := ep.WiFiAddr
		probeClient := e.Splicer.WiFiClient
		if probeLink == LinkCellular && ep.CellAddr != "" {
			targetIP = ep.CellAddr
			probeClient = e.Splicer.CellClient
		}
		if targetIP == "" {
			return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
		}
		probeURL := fmt.Sprintf("http://%s%s", net.JoinHostPort(targetIP, portStr), req.URL.RequestURI())
		probeReq, _ := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		probeReq.Host = req.Host
		for k, v := range req.Header {
			probeReq.Header[k] = v
		}
		probeReq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", reqStart, reqStart+spliceSegmentSize-1))
		resp, err := probeClient.Do(probeReq)
		if err != nil {
			return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusPartialContent {
			return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
		}
		totalSize = parseTotalSizeFromContentRange(resp.Header.Get("Content-Range"))
		if totalSize <= reqStart {
			return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
		}
		reqEnd = totalSize - 1
	}
	span := reqEnd - reqStart + 1
	if span < spliceSegmentSize {
		return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
	}
	return e.workStealRange(ctx, clientConn, req, ep, portStr, reqStart, reqEnd, totalSize)
}

// workStealRange fetches [start, end] in 256KB micro-segments using two
// persistent Keep-Alive workers (Wi-Fi + Cellular). Workers atomically claim
// segment indices; failed segments go to retryCh for the surviving worker to
// steal. Segments stream to the client in order as they complete.
func (e *OnPhoneCompoundEngine) workStealRange(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
	ep *DualEndpoint,
	portStr string,
	start, end, totalSize int64,
) error {
	numSeg := int((end-start)/spliceSegmentSize) + 1
	results := make([][]byte, numSeg)
	resCh := make(chan int, numSeg)      // completed segment indices
	retryCh := make(chan int, numSeg)     // failed segment indices to steal
	var nextSeg atomic.Int64
	var nextFlush atomic.Int64

	segRange := func(idx int) (int64, int64) {
		s := start + int64(idx)*spliceSegmentSize
		e := s + spliceSegmentSize - 1
		if e > end {
			e = end
		}
		return s, e
	}

	// Per-link target IPs and HTTP clients (persistent Keep-Alive).
	type linkTarget struct {
		link   LinkType
		ip     string
		client *http.Client
	}
	var targets []linkTarget
	if ep.WiFiAddr != "" {
		targets = append(targets, linkTarget{LinkWiFi, ep.WiFiAddr, e.Splicer.WiFiClient})
	}
	if ep.CellAddr != "" {
		targets = append(targets, linkTarget{LinkCellular, ep.CellAddr, e.Splicer.CellClient})
	}
	if len(targets) == 0 {
		return fmt.Errorf("workStealRange: no link targets")
	}

	fetchSeg := func(t linkTarget, idx int) {
		s, segEnd := segRange(idx)
		urlStr := fmt.Sprintf("http://%s%s", net.JoinHostPort(t.ip, portStr), req.URL.RequestURI())
		outReq, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			retryCh <- idx
			return
		}
		outReq.Host = req.Host
		for k, v := range req.Header {
			if !strings.EqualFold(k, "Range") {
				outReq.Header[k] = v
			}
		}
		outReq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", s, segEnd))
		t0 := time.Now()
		resp, err := t.client.Do(outReq)
		if err != nil {
			retryCh <- idx
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || (resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK) {
			retryCh <- idx
			return
		}
		// Trim body to the exact segment (server may ignore Range).
		want := int(segEnd - s + 1)
		if len(body) > want {
			body = body[:want]
		}
		if e.Binder != nil {
			e.Binder.OnBytes(int(t.link), int64(len(body)), 0)
		}
		RecordLinkGoodput(t.link, int64(len(body)), time.Since(t0))
		results[idx] = body
		resCh <- idx
	}

	// doneCh closes when all segments are flushed.
	doneCh := make(chan struct{})
	var wg sync.WaitGroup

	// Retry stealer: failed segments are retried on whichever link is free.
	// We fold retries into the worker loop via a shared claim function.
	claim := func() (int, bool) {
		// Prefer fresh segments within the sliding window, else steal retries.
		for {
			select {
			case idx := <-retryCh:
				return idx, true
			default:
			}
			idx := int(nextSeg.Add(1)) - 1
			if idx >= numSeg {
				// No fresh segments; drain retries only.
				select {
				case idx := <-retryCh:
					return idx, true
				default:
					return 0, false
				}
			}
			// Sliding window: don't run more than 8 segments ahead of flush.
			for int64(idx)-nextFlush.Load() >= spliceMaxInflight {
				select {
				case ridx := <-retryCh:
					return ridx, true
				case <-time.After(10 * time.Millisecond):
				}
			}
			return idx, true
		}
	}

	for _, t := range targets {
		wg.Add(1)
		go func(t linkTarget) {
			defer wg.Done()
			defer TrackFlow(t.link)()
			for {
				select {
				case <-ctx.Done():
					return
				case <-doneCh:
					return
				default:
				}
				idx, ok := claim()
				if !ok {
					// No work right now; check if we're done.
					select {
					case <-doneCh:
						return
					case <-time.After(20 * time.Millisecond):
						continue
					}
				}
				fetchSeg(t, idx)
			}
		}(t)
	}

	// Write 206 response headers for the original requested range.
	span := end - start + 1
	var hdrBuf bytes.Buffer
	fmt.Fprintf(&hdrBuf, "HTTP/1.1 206 Partial Content\r\n")
	hdrBuf.WriteString("Content-Type: application/octet-stream\r\n")
	hdrBuf.WriteString("Accept-Ranges: bytes\r\n")
	fmt.Fprintf(&hdrBuf, "Content-Range: bytes %d-%d/%d\r\n", start, end, totalSize)
	fmt.Fprintf(&hdrBuf, "Content-Length: %d\r\n", span)
	hdrBuf.WriteString("Connection: close\r\n\r\n")
	if _, err := clientConn.Write(hdrBuf.Bytes()); err != nil {
		close(doneCh)
		return err
	}

	// Stream segments in order as they complete.
	flushed := 0
	flushTimer := time.NewTimer(30 * time.Second)
	defer flushTimer.Stop()
	for flushed < numSeg {
		select {
		case <-resCh:
			// A segment completed; flush all consecutive ready segments.
			for flushed < numSeg && results[flushed] != nil {
				if _, err := clientConn.Write(results[flushed]); err != nil {
					close(doneCh)
					wg.Wait()
					return err
				}
				results[flushed] = nil // free memory
				flushed++
				nextFlush.Add(1)
			}
		case <-flushTimer.C:
			close(doneCh)
			wg.Wait()
			return fmt.Errorf("workStealRange: flush timeout")
		case <-ctx.Done():
			close(doneCh)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(doneCh)
	wg.Wait()
	return nil
}

// ForwardWithMidHandshakeReplay forwards an opaque TCP stream (TLS, banking,
// UPI, SSH) with dual-link SYN racing. If the winning link stalls before
// returning the first response byte, the initial payload (ClientHello) is
// replayed on the standby link.
//
// This works because:
//  1. gonet.TCPConn is a userspace endpoint - swapping the upstream net.Conn
//     before any response bytes is just changing a variable.
//  2. TLS ClientHello replay on a new TCP socket is valid - the app holds the
//     ephemeral private key and completes with any valid ServerHello
//     (RFC 8446).
//
// NOTE: firstPayload must be the COMPLETE initial client payload (e.g. the
// full TLS ClientHello record), not a truncated peek. The old io.MultiReader
// 8-byte peek caused every TLS handshake to time out.
func (e *OnPhoneCompoundEngine) ForwardWithMidHandshakeReplay(
	ctx context.Context,
	clientConn net.Conn,
	firstPayload []byte,
	ep *DualEndpoint,
	port string,
) error {
	raceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Pass preferred = 0 so StripedPreferredLink() spreads parallel TCP
	// streams across Wi-Fi & Cellular instead of Wi-Fi winning every race.
	primaryConn, primaryLink, standbyCh, err := DialSpeculativeDualLink(raceCtx, e.Binder, ep, port, 0)
	if err != nil {
		return err
	}

	var standbyUsed atomic.Bool
	drainStandby := func() {
		go func() {
			for res := range standbyCh {
				if res.err == nil && res.conn != nil {
					res.conn.Close()
				}
			}
		}()
	}
	// Always drain standbyCh in background if unused so standby sockets never leak.
	defer func() {
		if !standbyUsed.Load() {
			drainStandby()
		}
	}()

	getStandby := func() (net.Conn, LinkType) {
		if !standbyUsed.CompareAndSwap(false, true) {
			return nil, 0
		}
		select {
		case res, ok := <-standbyCh:
			if ok && res.err == nil && res.conn != nil {
				return res.conn, res.link
			}
		case <-time.After(1500 * time.Millisecond):
			drainStandby()
		}
		return nil, 0
	}

	activeUpstream := primaryConn
	activeLink := primaryLink

	if len(firstPayload) > 0 {
		_, wErr := activeUpstream.Write(firstPayload)
		if wErr != nil {
			// Primary write failed immediately; sideline it and try standby
			MarkLinkStalled(activeLink, 3*time.Second)
			if sbConn, sbLink := getStandby(); sbConn != nil {
				activeUpstream.Close()
				activeUpstream = sbConn
				activeLink = sbLink
				if _, wErr2 := activeUpstream.Write(firstPayload); wErr2 != nil {
					activeUpstream.Close()
					return wErr2
				}
			} else {
				activeUpstream.Close()
				return wErr
			}
		} else {
			if e.Binder != nil {
				e.Binder.OnBytes(int(activeLink), 0, int64(len(firstPayload)))
			}
			// Wait up to 1.5s for first response packet (ServerHello)
			_ = activeUpstream.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			firstResp := make([]byte, 8192)
			rn, rErr := activeUpstream.Read(firstResp)
			_ = activeUpstream.SetReadDeadline(time.Time{})

			if rn > 0 {
				if e.Binder != nil {
					e.Binder.OnBytes(int(activeLink), int64(rn), 0)
				}
				if _, err := clientConn.Write(firstResp[:rn]); err != nil {
					activeUpstream.Close()
					return err
				}
			} else if rErr != nil {
				// Primary failed/stalled with 0 bytes received. Sideline it
				// so the next burst of sockets steers to the healthy radio.
				// Only switch if standby is live!
				MarkLinkStalled(activeLink, 3*time.Second)
				if sbConn, sbLink := getStandby(); sbConn != nil {
					activeUpstream.Close()
					activeUpstream = sbConn
					activeLink = sbLink
					if _, err := activeUpstream.Write(firstPayload); err != nil {
						activeUpstream.Close()
						return err
					}
					if e.Binder != nil {
						e.Binder.OnBytes(int(activeLink), 0, int64(len(firstPayload)))
					}
				} else if !isTimeoutErr(rErr) {
					activeUpstream.Close()
					return rErr
				}
			}
		}
	}

	defer activeUpstream.Close()
	// Track this active flow for the full lifetime of the TCP stream!
	defer TrackFlow(activeLink)()

	errCh := make(chan error, 2)
	go func() {
		// Upload: client -> upstream (real-time byte counting, 128KB buffers)
		upWriter := &byteCounterWriter{w: activeUpstream, binder: e.Binder, link: activeLink, isUpload: true}
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		_, err := io.CopyBuffer(upWriter, clientConn, *bufPtr)
		if cw, ok := activeUpstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errCh <- err
	}()
	go func() {
		// Download: upstream -> client (real-time byte counting, 128KB buffers)
		downWriter := &byteCounterWriter{w: clientConn, binder: e.Binder, link: activeLink, isUpload: false}
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		_, err := io.CopyBuffer(downWriter, activeUpstream, *bufPtr)
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errCh <- err
	}()
	<-errCh
	<-errCh
	return nil
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

// compoundHTTPStream handles HTTP GET with range-based compounding.
func (e *OnPhoneCompoundEngine) compoundHTTPStream(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
	ep *DualEndpoint,
	portStr string,
) error {
	// Probe first 256KB to check range support and get total size
	probeEnd := int64(256*1024 - 1)

	// Pick best link for probe
	probeLink := e.Scheduler.PickOptimalLink(256 * 1024)
	targetIP := ep.WiFiAddr
	probeClient := e.Splicer.WiFiClient
	if probeLink == LinkCellular && ep.CellAddr != "" {
		targetIP = ep.CellAddr
		probeClient = e.Splicer.CellClient
	}
	if targetIP == "" {
		return fmt.Errorf("no target IP for probe")
	}

	probeURL := fmt.Sprintf("http://%s%s", net.JoinHostPort(targetIP, portStr), req.URL.RequestURI())
	probeReq, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		return err
	}
	probeReq.Host = req.Host
	for k, v := range req.Header {
		probeReq.Header[k] = v
	}
	probeReq.Header.Set("Range", fmt.Sprintf("bytes=0-%d", probeEnd))

	resp, err := probeClient.Do(probeReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	totalSize := parseTotalSizeFromContentRange(resp.Header.Get("Content-Range"))
	if resp.StatusCode != http.StatusPartialContent || totalSize < MinCompoundSize {
		// Not splittable or too small: stream directly
		resp.StatusCode = http.StatusOK
		resp.Status = "200 OK"
		resp.Header.Del("Content-Range")
		return resp.Write(clientConn)
	}

	// Splittable! Synthesize 200 OK and compound the rest
	etag := resp.Header.Get("ETag")
	if etag == "" {
		etag = resp.Header.Get("Last-Modified")
	}

	// Write headers
	resp.Header.Del("Content-Range")
	resp.Header.Set("Content-Length", strconv.FormatInt(totalSize, 10))
	resp.StatusCode = http.StatusOK
	resp.Status = "200 OK"

	var hdrBuf bytes.Buffer
	fmt.Fprintf(&hdrBuf, "HTTP/%d.%d 200 OK\r\n", resp.ProtoMajor, resp.ProtoMinor)
	_ = resp.Header.Write(&hdrBuf)
	hdrBuf.WriteString("\r\n")
	if _, err := clientConn.Write(hdrBuf.Bytes()); err != nil {
		return err
	}

	// Stream the probed 256KB
	written, err := io.Copy(clientConn, resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Compound the remainder with HalvingSplicer
	return e.Splicer.StreamWithDynamicHalving(
		ctx,
		clientConn,
		req,
		ep,
		portStr,
		etag,
		written,
		totalSize,
	)
}

// passThroughHTTP forwards an HTTP request on the best link without compounding.
func (e *OnPhoneCompoundEngine) passThroughHTTP(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
	ep *DualEndpoint,
	portStr string,
) error {
	link := e.Scheduler.PickOptimalLink(128 * 1024)
	targetIP := ep.WiFiAddr
	client := e.Splicer.WiFiClient
	if link == LinkCellular && ep.CellAddr != "" {
		targetIP = ep.CellAddr
		client = e.Splicer.CellClient
	}
	if targetIP == "" {
		return fmt.Errorf("no target IP")
	}

	urlStr := fmt.Sprintf("http://%s%s", net.JoinHostPort(targetIP, portStr), req.URL.RequestURI())
	outReq, err := http.NewRequestWithContext(ctx, req.Method, urlStr, req.Body)
	if err != nil {
		return err
	}
	outReq.Host = req.Host
	outReq.Header = req.Header.Clone()

	resp, err := client.Do(outReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return resp.Write(clientConn)
}

// parseTotalSizeFromContentRange parses "bytes 0-262143/104857600" -> 104857600
func parseTotalSizeFromContentRange(cr string) int64 {
	if !strings.HasPrefix(cr, "bytes ") {
		return -1
	}
	slashIdx := strings.LastIndex(cr, "/")
	if slashIdx == -1 || slashIdx+1 >= len(cr) {
		return -1
	}
	totalStr := cr[slashIdx+1:]
	if totalStr == "*" {
		return -1
	}
	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil {
		return -1
	}
	return total
}

var _ = sync.Once{}
