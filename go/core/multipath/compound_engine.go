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

// byteCounterWriter wraps an io.Writer to report bytes in real-time via the binder.
type byteCounterWriter struct {
	w        io.Writer
	binder   SocketBinder
	link     int
	isUpload bool
}

func (bw *byteCounterWriter) Write(p []byte) (int, error) {
	n, err := bw.w.Write(p)
	if n > 0 && bw.binder != nil {
		if bw.isUpload {
			bw.binder.OnBytes(bw.link, 0, int64(n))
		} else {
			bw.binder.OnBytes(bw.link, int64(n), 0)
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

	// If client already requested a range, pass through
	if req.Header.Get("Range") != "" {
		return e.passThroughHTTP(ctx, clientConn, req, ep, portStr)
	}

	// Probe for range support and file size
	return e.compoundHTTPStream(ctx, clientConn, req, ep, portStr)
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
			// Primary write failed immediately; try standby
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
				// Primary failed/stalled with 0 bytes received. Only switch if standby is live!
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
		// Upload: client -> upstream (real-time byte counting)
		upWriter := &byteCounterWriter{w: activeUpstream, binder: e.Binder, link: int(activeLink), isUpload: true}
		_, err := io.Copy(upWriter, clientConn)
		if cw, ok := activeUpstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errCh <- err
	}()
	go func() {
		// Download: upstream -> client (real-time byte counting)
		downWriter := &byteCounterWriter{w: clientConn, binder: e.Binder, link: int(activeLink), isUpload: false}
		_, err := io.Copy(downWriter, activeUpstream)
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
