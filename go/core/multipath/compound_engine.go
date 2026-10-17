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

const (
	MinCompoundSize int64 = 256 * 1024 // 256 KB minimum for single-stream HTTP range splicing
)

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 128*1024)
		return &b
	},
}

type byteCounterWriter struct {
	w        io.Writer
	binder   SocketBinder
	sched    *Scheduler
	link     LinkType
	isUpload bool
}

func (bw *byteCounterWriter) Write(p []byte) (int, error) {
	start := time.Now()
	n, err := bw.w.Write(p)
	if n > 0 {
		RecordLinkBytes(bw.link, int64(n))
		if bw.sched != nil {
			bw.sched.RecordBytes(bw.link, int64(n), time.Since(start))
		}
		if bw.binder != nil {
			if bw.isUpload {
				bw.binder.OnBytes(int(bw.link), 0, int64(n))
			} else {
				bw.binder.OnBytes(int(bw.link), int64(n), 0)
			}
		}
	}
	return n, err
}

func (e *OnPhoneCompoundEngine) HandleGVisorTCPStream(
	ctx context.Context,
	clientConn net.Conn,
	ep *DualEndpoint,
	dstPort uint16,
) error {
	defer clientConn.Close()
	portStr := strconv.Itoa(int(dstPort))

	// Read full initial payload (up to 16 KB) directly from clientConn (fixes the 8-byte MultiReader truncation bug!)
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	firstChunk := make([]byte, 16384)
	n, _ := clientConn.Read(firstChunk)

	// If TLS Handshake (0x16), ensure the complete ClientHello record is read in one shot
	if n >= 5 && firstChunk[0] == 0x16 {
		recLen := 5 + (int(firstChunk[3])<<8 | int(firstChunk[4]))
		if recLen > n && recLen <= len(firstChunk) {
			extra, _ := io.ReadFull(clientConn, firstChunk[n:recLen])
			n += extra
		}
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	replayedReader := io.MultiReader(bytes.NewReader(firstChunk[:n]), clientConn)

	// Non-HTTP GET (TLS/443, POST uploads, protocols): use Dual-Link Striping + Standby Replay
	if n < 4 || string(firstChunk[:4]) != "GET " {
		return e.ForwardWithMidHandshakeReplay(ctx, clientConn, replayedReader, ep, portStr)
	}

	// Plain HTTP GET: parse request and compound over both links
	bufReader := bufio.NewReader(replayedReader)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return err
	}
	return e.compoundHTTPStream(ctx, clientConn, req, ep, portStr)
}

func (e *OnPhoneCompoundEngine) ForwardWithMidHandshakeReplay(
	ctx context.Context,
	clientConn net.Conn,
	initialReader io.Reader,
	ep *DualEndpoint,
	port string,
) error {
	raceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var preferred LinkType
	var stagger time.Duration
	if e.MPSched != nil {
		preferred, _, stagger = e.MPSched.SelectLinks(256 * 1024)
	}
	dialStart := time.Now()
	primaryConn, primaryLink, standbyCh, err := DialSpeculativeDualLink(raceCtx, e.Binder, ep, port, preferred, stagger)
	if err != nil {
		if e.MPSched != nil && preferred != 0 {
			e.MPSched.RecordFailure(preferred)
		}
		return err
	}
	if e.MPSched != nil {
		e.MPSched.RecordRTT(primaryLink, time.Since(dialStart))
		e.MPSched.RecordSuccess(primaryLink)
	}
	var standbyUsed atomic.Bool
	recycleStandby := func() {
		if !standbyUsed.CompareAndSwap(false, true) {
			return
		}
		go func() {
			for res := range standbyCh {
				if res.err == nil && res.conn != nil {
					PutWarmConn(res.link, res.ip, port, res.conn)
				}
			}
		}()
	}
	defer recycleStandby()
	popStandby := func() (net.Conn, LinkType) {
		if !standbyUsed.CompareAndSwap(false, true) {
			return nil, 0
		}
		select {
		case res, ok := <-standbyCh:
			if ok && res.err == nil && res.conn != nil {
				return res.conn, res.link
			}
		case <-time.After(1500 * time.Millisecond):
			go func() {
				for res := range standbyCh {
					if res.err == nil && res.conn != nil {
						res.conn.Close()
					}
				}
			}()
		}
		return nil, 0
	}
	firstPayload := make([]byte, 16384)
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	n, _ := initialReader.Read(firstPayload)
	if n > 0 && n <= 16 {
		m, _ := initialReader.Read(firstPayload[n:])
		n += m
	}
	if n >= 5 && firstPayload[0] == 0x16 {
		recLen := 5 + (int(firstPayload[3])<<8 | int(firstPayload[4]))
		if recLen > n && recLen <= len(firstPayload) {
			extra, _ := io.ReadFull(initialReader, firstPayload[n:recLen])
			n += extra
		}
	}
	_ = clientConn.SetReadDeadline(time.Time{})
	activeUpstream := primaryConn
	activeLink := primaryLink
	if n > 0 {
		wStart := time.Now()
		if _, wErr := WriteClientHello(activeUpstream, firstPayload[:n]); wErr != nil {
			MarkLinkStalled(activeLink, 3*time.Second)
			if e.MPSched != nil {
				e.MPSched.RecordFailure(activeLink)
			}
			if sbConn, sbLink := popStandby(); sbConn != nil {
				activeUpstream.Close()
				activeUpstream = sbConn
				activeLink = sbLink
				if _, wErr2 := WriteClientHello(activeUpstream, firstPayload[:n]); wErr2 != nil {
					if e.MPSched != nil {
						e.MPSched.RecordFailure(activeLink)
					}
					activeUpstream.Close()
					return wErr2
				}
			} else {
				activeUpstream.Close()
				return wErr
			}
		} else {
			RecordLinkBytes(activeLink, int64(n))
			if e.MPSched != nil {
				e.MPSched.RecordBytes(activeLink, int64(n), time.Since(wStart))
			}
			if e.Binder != nil {
				e.Binder.OnBytes(int(activeLink), 0, int64(n))
			}
			_ = activeUpstream.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
			firstResp := make([]byte, 16384)
			rStart := time.Now()
			rn, rErr := activeUpstream.Read(firstResp)
			_ = activeUpstream.SetReadDeadline(time.Time{})
			if rn > 0 {
				recycleStandby()
				RecordLinkBytes(activeLink, int64(rn))
				if e.MPSched != nil {
					e.MPSched.RecordRTT(activeLink, time.Since(rStart))
					e.MPSched.RecordBytes(activeLink, int64(rn), time.Since(rStart))
				}
				if e.Binder != nil {
					e.Binder.OnBytes(int(activeLink), int64(rn), 0)
				}
				if _, err := clientConn.Write(firstResp[:rn]); err != nil {
					activeUpstream.Close()
					return err
				}
			} else if rErr != nil {
				MarkLinkStalled(activeLink, 3*time.Second)
				if e.MPSched != nil {
					e.MPSched.RecordFailure(activeLink)
				}
				if sbConn, sbLink := popStandby(); sbConn != nil {
					activeUpstream.Close()
					activeUpstream = sbConn
					activeLink = sbLink
					if _, err := WriteClientHello(activeUpstream, firstPayload[:n]); err != nil {
						if e.MPSched != nil {
							e.MPSched.RecordFailure(activeLink)
						}
						activeUpstream.Close()
						return err
					}
					RecordLinkBytes(activeLink, int64(n))
					if e.Binder != nil {
						e.Binder.OnBytes(int(activeLink), 0, int64(n))
					}
				} else if !isTimeoutErr(rErr) {
					activeUpstream.Close()
					return rErr
				}
			}
		}
	} else {
		recycleStandby()
	}
	defer activeUpstream.Close()
	defer TrackFlow(activeLink)()
	if e.MPSched != nil {
		e.MPSched.AcquireFlow(activeLink)
		defer e.MPSched.ReleaseFlow(activeLink)
	}
	errCh := make(chan error, 2)
	go func() {
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		upWriter := &byteCounterWriter{w: activeUpstream, binder: e.Binder, sched: e.MPSched, link: activeLink, isUpload: true}
		_, err := io.CopyBuffer(upWriter, initialReader, *bufPtr)
		if cw, ok := activeUpstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errCh <- err
	}()
	go func() {
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)
		downWriter := &byteCounterWriter{w: clientConn, binder: e.Binder, sched: e.MPSched, link: activeLink, isUpload: false}
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

func (e *OnPhoneCompoundEngine) passThroughHTTP(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
	ep *DualEndpoint,
	port string,
) error {
	var reqBuf bytes.Buffer
	if err := req.Write(&reqBuf); err != nil {
		return err
	}
	replayed := io.MultiReader(&reqBuf, clientConn)
	return e.ForwardWithMidHandshakeReplay(ctx, clientConn, replayed, ep, port)
}

// dialSplicerLink opens a metered, scheduler-fed connection pinned to one link
// for HTTP range-splicer workers. Every byte feeds the BDP scheduler's per-link
// goodput/RTT estimates and re-arms TCP_QUICKACK, so the scheduler learns real
// radio capacity from bulk traffic. Falls back to the plain bound dialer when
// the racer is unavailable (unit tests) or the metered dial fails.
func (e *OnPhoneCompoundEngine) dialSplicerLink(ctx context.Context, link LinkType, ip, fallbackIP, port string) (net.Conn, error) {
	if e.Racer != nil {
		if portInt, err := strconv.Atoi(port); err == nil {
			if mc, derr := e.Racer.DialLink(ctx, "tcp", link, ip, portInt); derr == nil {
				return mc, nil
			}
		}
	}
	return DialLinkConn(ctx, e.Binder, link, ip, fallbackIP, port)
}

// selectSegmentSize returns the segment size for the given segment index:
// fast 512KB first two segments, then 2MB (4MB for large files).
func selectSegmentSize(totalSpan int64, segmentIndex int64) int64 {
	if segmentIndex < 2 {
		return 512 * 1024
	}
	if totalSpan >= 100*1024*1024 {
		return 4 * 1024 * 1024
	}
	return 2 * 1024 * 1024
}

// compoundHTTPStream compounds a single HTTP GET (including explicit Range requests)
// across BOTH Wi-Fi and Cellular simultaneously using work-stealing segments.
func (e *OnPhoneCompoundEngine) compoundHTTPStream(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
	ep *DualEndpoint,
	port string,
) error {
	SanitizePrivacyHeaders(req.Header)
	wifiAddr, cellAddr := ep.WaitReady(ctx)
	if wifiAddr == "" && cellAddr == "" {
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	probeConn, probeLink, standbyCh, err := DialSpeculativeDualLink(probeCtx, e.Binder, ep, port, 0, 0)
	if err != nil {
		return err
	}
	go func() {
		for res := range standbyCh {
			if res.err == nil && res.conn != nil {
				PutWarmConn(res.link, res.ip, port, res.conn)
			}
		}
	}()
	clientRange := req.Header.Get("Range")
	var reqStart, reqEnd, totalSize int64
	hasExplicitEnd := false
	if strings.HasPrefix(clientRange, "bytes=") {
		parts := strings.SplitN(strings.TrimPrefix(clientRange, "bytes="), "-", 2)
		if len(parts) == 2 {
			reqStart, _ = strconv.ParseInt(parts[0], 10, 64)
			if parts[1] != "" {
				reqEnd, _ = strconv.ParseInt(parts[1], 10, 64)
				hasExplicitEnd = true
			}
		}
	}
	probeReq := req.Clone(probeCtx)
	SanitizePrivacyHeaders(probeReq.Header)
	if clientRange == "" {
		probeReq.Header.Set("Range", "bytes=0-0")
	} else {
		probeReq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", reqStart, reqStart))
	}
	if err := probeReq.Write(probeConn); err != nil {
		probeConn.Close()
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	br := bufio.NewReader(probeConn)
	probeResp, err := http.ReadResponse(br, probeReq)
	if err != nil {
		probeConn.Close()
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	_, _ = io.CopyN(io.Discard, probeResp.Body, 1)
	probeResp.Body.Close()
	probeConn.Close()
	cr := probeResp.Header.Get("Content-Range")
	if probeResp.StatusCode != http.StatusPartialContent || !strings.HasPrefix(cr, "bytes ") {
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	slashIdx := strings.LastIndexByte(cr, '/')
	if slashIdx < 0 {
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	totalSize, err = strconv.ParseInt(cr[slashIdx+1:], 10, 64)
	if err != nil || totalSize <= 0 {
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	if !hasExplicitEnd || reqEnd >= totalSize {
		reqEnd = totalSize - 1
	}
	span := reqEnd - reqStart + 1
	if span < MinCompoundSize {
		return e.passThroughHTTP(ctx, clientConn, req, ep, port)
	}
	statusLine := "HTTP/1.1 200 OK\r\n"
	if clientRange != "" {
		statusLine = "HTTP/1.1 206 Partial Content\r\n"
		probeResp.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", reqStart, reqEnd, totalSize))
	} else {
		probeResp.Header.Del("Content-Range")
	}
	probeResp.Header.Set("Content-Length", strconv.FormatInt(span, 10))
	probeResp.Header.Del("Transfer-Encoding")
	var hdrBuf bytes.Buffer
	hdrBuf.WriteString(statusLine)
	_ = probeResp.Header.Write(&hdrBuf)
	hdrBuf.WriteString("\r\n")
	if _, err := clientConn.Write(hdrBuf.Bytes()); err != nil {
		return err
	}
	segOffsets := []int64{reqStart}
	for off := reqStart; off <= reqEnd; {
		sz := selectSegmentSize(span, int64(len(segOffsets)-1))
		if off+sz > reqEnd+1 {
			sz = reqEnd + 1 - off
		}
		if sz <= 0 {
			break
		}
		off += sz
		segOffsets = append(segOffsets, off)
	}
	numSegs := len(segOffsets) - 1
	type segResult struct {
		data []byte
		err  error
	}
	results := make([]chan segResult, numSegs)
	for i := range results {
		results[i] = make(chan segResult, 1)
	}
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	var nextSeg atomic.Int32
	var flushIdx atomic.Int32
	retryCh := make(chan int, numSegs)
	segAttempts := make([]atomic.Int32, numSegs)
	worker := func(initialLink LinkType, initialIP, initialFallback string) {
		curLink := initialLink
		curIP := initialIP
		curFallback := initialFallback
		defer TrackFlow(curLink)()
		var conn net.Conn
		var connBr *bufio.Reader
		defer func() {
			if conn != nil {
				conn.Close()
			}
		}()
		fetchSeg := func(idx int) ([]byte, bool, error) {
			sStart := segOffsets[idx]
			sEnd := segOffsets[idx+1] - 1
			expected := int(sEnd - sStart + 1)
			if conn == nil {
				c, dErr := e.dialSplicerLink(sctx, curLink, curIP, curFallback, port)
				if dErr != nil {
					// Dial failed (e.g. this radio just dropped): signal dialFail=true
					// so we can seamlessly fail the worker over to the live radio!
					return nil, true, dErr
				}
				conn = c
				connBr = bufio.NewReaderSize(conn, 128*1024)
			}
			rClone := req.Clone(sctx)
			SanitizePrivacyHeaders(rClone.Header)
			rClone.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", sStart, sEnd))
			rClone.Header.Set("Connection", "keep-alive")
			const segStallTimeout = 12 * time.Second
			_ = conn.SetDeadline(time.Now().Add(segStallTimeout))
			if err := rClone.Write(conn); err != nil {
				conn.Close()
				conn = nil
				return nil, false, err
			}
			resp, err := http.ReadResponse(connBr, rClone)
			if err != nil {
				conn.Close()
				conn = nil
				return nil, false, err
			}
			if resp.StatusCode != http.StatusPartialContent {
				resp.Body.Close()
				conn.Close()
				conn = nil
				return nil, false, fmt.Errorf("unexpected status %d", resp.StatusCode)
			}
			buf := make([]byte, expected)
			readBytes := 0
			for readBytes < expected {
				n, rErr := resp.Body.Read(buf[readBytes:])
				if n > 0 {
					readBytes += n
					_ = conn.SetDeadline(time.Now().Add(segStallTimeout))
					RecordLinkBytes(curLink, int64(n))
					if e.Binder != nil {
						e.Binder.OnBytes(int(curLink), int64(n), 0)
					}
				}
				if rErr != nil {
					resp.Body.Close()
					conn.Close()
					conn = nil
					if rErr == io.EOF && readBytes == expected {
						break
					}
					return nil, false, rErr
				}
			}
			resp.Body.Close()
			_ = conn.SetDeadline(time.Time{})
			return buf, false, nil
		}
		for {
			for nextSeg.Load()-flushIdx.Load() > 10 {
				select {
				case <-sctx.Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
			var idx int
			select {
			case idx = <-retryCh:
			default:
				idx = int(nextSeg.Add(1) - 1)
				if idx >= numSegs {
					select {
					case idx = <-retryCh:
					case <-sctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
						if int(flushIdx.Load()) >= numSegs {
							return
						}
						continue
					}
				}
			}
			data, dialFailed, err := fetchSeg(idx)
			if err != nil {
				// If the radio itself could not bind/connect (single-radio mode or Wi-Fi dropped),
				// pivot this worker to the other radio instead of poisoning segAttempts!
				if dialFailed {
					if curLink == LinkWiFi && cellAddr != "" {
						curLink, curIP, curFallback = LinkCellular, cellAddr, wifiAddr
					} else if curLink == LinkCellular && wifiAddr != "" {
						curLink, curIP, curFallback = LinkWiFi, wifiAddr, cellAddr
					}
				}
				select {
				case <-sctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
				data, _, err = fetchSeg(idx)
				if err != nil {
					if segAttempts[idx].Add(1) >= 4 {
						results[idx] <- segResult{err: err}
						return
					}
					select {
					case retryCh <- idx:
					default:
						results[idx] <- segResult{err: err}
						return
					}
					continue
				}
			}
			results[idx] <- segResult{data: data}
		}
	}
	// Launch workers across available links. If one link is offline at start,
	// worker() automatically pivots onto the live radio on its first dial.
	if wifiAddr != "" && cellAddr != "" {
		go worker(LinkWiFi, wifiAddr, cellAddr)
		go worker(LinkCellular, cellAddr, wifiAddr)
		go worker(LinkWiFi, wifiAddr, cellAddr)
		go worker(LinkCellular, cellAddr, wifiAddr)
	} else {
		// Single-radio resolved: launch 3 pipelined workers on the active link
		// to keep the 4G/5G or Wi-Fi BDP pipe 100% full across segment boundaries.
		activeIP := wifiAddr
		if activeIP == "" {
			activeIP = cellAddr
		}
		if probeLink == 0 {
			probeLink = LinkCellular
		}
		for w := 0; w < 3; w++ {
			go worker(probeLink, activeIP, activeIP)
		}
	}
	for i := 0; i < numSegs; i++ {
		select {
		case res := <-results[i]:
			if res.err != nil {
				return res.err
			}
			if _, err := clientConn.Write(res.data); err != nil {
				return err
			}
			flushIdx.Store(int32(i + 1))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}
