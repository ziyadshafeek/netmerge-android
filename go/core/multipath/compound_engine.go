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
	"time"
)

// MinCompoundSize is the minimum file size for range-based compounding.
// Files smaller than this are streamed directly on the best link.
const MinCompoundSize int64 = 512 * 1024

// HandleGVisorTCPStream is called for every TCP connection from the app.
// It peeks at the first bytes to determine the protocol:
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

	// Peek first 8 bytes to detect protocol
	_ = clientConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	peekBuf := make([]byte, 8)
	n, _ := clientConn.Read(peekBuf)
	_ = clientConn.SetReadDeadline(time.Time{})

	replayedReader := io.MultiReader(bytes.NewReader(peekBuf[:n]), clientConn)

	// If NOT a plain HTTP GET, use speculative racing with replay
	if n < 4 || string(peekBuf[:4]) != "GET " {
		return e.ForwardWithMidHandshakeReplay(ctx, clientConn, replayedReader, ep, portStr)
	}

	// It's HTTP GET - parse the request
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
func (e *OnPhoneCompoundEngine) ForwardWithMidHandshakeReplay(
	ctx context.Context,
	clientConn net.Conn,
	initialReader io.Reader,
	ep *DualEndpoint,
	port string,
) error {
	// Race both links
	raceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	primaryConn, primaryLink, standbyCh, err := DialSpeculativeDualLink(raceCtx, e.Binder, ep, port, e.Scheduler.PickOptimalLink(64*1024))
	if err != nil {
		return err
	}

	// Get standby connection (if available)
	var standbyConn net.Conn
	var standbyLink LinkType
	select {
	case res := <-standbyCh:
		if res.err == nil {
			standbyConn = res.conn
			standbyLink = res.link
		}
	case <-time.After(500 * time.Millisecond):
		// No standby available
	}

	// Ensure standby is closed if not used
	defer func() {
		if standbyConn != nil {
			standbyConn.Close()
		}
	}()

	// Read initial payload (e.g., ClientHello)
	firstPayload := make([]byte, 8192)
	_ = clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, readErr := initialReader.Read(firstPayload)
	_ = clientConn.SetReadDeadline(time.Time{})

	activeUpstream := primaryConn
	activeLink := primaryLink

	if n > 0 {
		// Send on primary
		if _, wErr := activeUpstream.Write(firstPayload[:n]); wErr != nil {
			// Primary failed immediately, try standby
			if standbyConn != nil {
				activeUpstream.Close()
				activeUpstream = standbyConn
				activeLink = standbyLink
				standbyConn = nil
				if _, wErr2 := activeUpstream.Write(firstPayload[:n]); wErr2 != nil {
					activeUpstream.Close()
					return wErr2
				}
			} else {
				activeUpstream.Close()
				return wErr
			}
		} else {
			// Wait for first response byte with timeout
			_ = activeUpstream.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			firstResp := make([]byte, 8192)
			rn, rErr := activeUpstream.Read(firstResp)
			_ = activeUpstream.SetReadDeadline(time.Time{})

			if rn > 0 {
				// Primary responded! Write to client and continue
				if _, err := clientConn.Write(firstResp[:rn]); err != nil {
					activeUpstream.Close()
					return err
				}
				// Close standby, we don't need it
				if standbyConn != nil {
					standbyConn.Close()
					standbyConn = nil
				}
			} else if rErr != nil && standbyConn != nil {
				// Primary stalled! Replay on standby
				activeUpstream.Close()
				activeUpstream = standbyConn
				activeLink = standbyLink
				standbyConn = nil
				if _, err := activeUpstream.Write(firstPayload[:n]); err != nil {
					activeUpstream.Close()
					return err
				}
				// Read response from standby and forward
				_ = activeUpstream.SetReadDeadline(time.Now().Add(5 * time.Second))
				rn2, rErr2 := activeUpstream.Read(firstResp)
				_ = activeUpstream.SetReadDeadline(time.Time{})
				if rn2 > 0 {
					if _, err := clientConn.Write(firstResp[:rn2]); err != nil {
						activeUpstream.Close()
						return err
					}
				} else if rErr2 != nil {
					activeUpstream.Close()
					return rErr2
				}
			}
		}
	} else if readErr != nil {
		activeUpstream.Close()
		return readErr
	}

	defer activeUpstream.Close()

	// Full-duplex relay with goodput tracking
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(activeUpstream, initialReader)
		errCh <- err
	}()
	go func() {
		start := time.Now()
		written, err := io.Copy(clientConn, activeUpstream)
		// Record for ECT scheduler
		if activeLink == LinkWiFi {
			e.Scheduler.WiFi.RecordTransfer(written, time.Since(start))
		} else {
			e.Scheduler.Cell.RecordTransfer(written, time.Since(start))
		}
		errCh <- err
	}()

	return <-errCh
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
