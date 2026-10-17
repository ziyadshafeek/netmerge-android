// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

var (
	activeFlows    [3]atomic.Int64 // live TCP streams per link (1=WiFi, 2=Cellular)
	ewmaGoodput    [3]atomic.Int64 // bytes/sec EWMA per link
	ewmaRTTMicros  [3]atomic.Int64 // RTT in microseconds per link
	stalledUntil   [3]atomic.Int64 // unix nano cooldown when a link stalls
	rrCounter      atomic.Uint64
)

// RecordLinkRTT updates the EWMA RTT for a link.
func RecordLinkRTT(link LinkType, rtt time.Duration) {
	if link != LinkWiFi && link != LinkCellular {
		return
	}
	us := rtt.Microseconds()
	if us <= 0 {
		us = 1000
	}
	old := ewmaRTTMicros[link].Load()
	if old == 0 {
		ewmaRTTMicros[link].Store(us)
	} else {
		ewmaRTTMicros[link].Store((old*3 + us) / 4)
	}
}

// RecordLinkGoodput updates the EWMA throughput (bytes/sec) for a link.
func RecordLinkGoodput(link LinkType, bytes int64, elapsed time.Duration) {
	if (link != LinkWiFi && link != LinkCellular) || bytes < 16*1024 || elapsed <= 0 {
		return
	}
	bps := int64(float64(bytes) / elapsed.Seconds())
	old := ewmaGoodput[link].Load()
	if old == 0 {
		ewmaGoodput[link].Store(bps)
	} else {
		// Fast attack (50/50) when throughput rises, slower decay (80/20)
		if bps > old {
			ewmaGoodput[link].Store((old + bps) / 2)
		} else {
			ewmaGoodput[link].Store((old*4 + bps) / 5)
		}
	}
}

// MarkLinkStalled temporarily penalizes a link that failed or timed out mid-handshake.
func MarkLinkStalled(link LinkType, d time.Duration) {
	if link == LinkWiFi || link == LinkCellular {
		stalledUntil[link].Store(time.Now().Add(d).UnixNano())
	}
}

// StripedPreferredLink selects the link that maximizes per-flow throughput:
// Score(link) = Goodput(link) / (ActiveFlows(link) + 1).
// During cold start (before both links have measured goodput), it alternates
// based on fewest active flows so both links are immediately probed and utilized.
func StripedPreferredLink() LinkType {
	now := time.Now().UnixNano()
	wifiStalled := now < stalledUntil[LinkWiFi].Load()
	cellStalled := now < stalledUntil[LinkCellular].Load()
	if wifiStalled && !cellStalled {
		return LinkCellular
	}
	if cellStalled && !wifiStalled {
		return LinkWiFi
	}
	wFlows := activeFlows[LinkWiFi].Load()
	cFlows := activeFlows[LinkCellular].Load()
	wBps := ewmaGoodput[LinkWiFi].Load()
	cBps := ewmaGoodput[LinkCellular].Load()
	// Cold start or unmeasured link: ensure both links get flows to measure speed
	if wBps < 64*1024 || cBps < 64*1024 {
		if cFlows < wFlows {
			return LinkCellular
		}
		if wFlows < cFlows {
			return LinkWiFi
		}
		if rrCounter.Add(1)%2 == 0 {
			return LinkCellular
		}
		return LinkWiFi
	}
	// Capacity-weighted per-flow bandwidth score: Goodput / (activeFlows + 1)
	wScore := float64(wBps) / float64(wFlows+1)
	cScore := float64(cBps) / float64(cFlows+1)
	if cScore > wScore {
		return LinkCellular
	}
	return LinkWiFi
}

// TrackFlow increments the active flow counter for the lifetime of a TCP stream.
func TrackFlow(link LinkType) func() {
	activeFlows[link].Add(1)
	return func() { activeFlows[link].Add(-1) }
}

func toNAT64(ip4 net.IP) string {
	ip4 = ip4.To4()
	if ip4 == nil {
		return ""
	}
	return net.IP{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, ip4[0], ip4[1], ip4[2], ip4[3]}.String()
}

// raceResult is the outcome of dialing one link.
type raceResult struct {
	conn net.Conn
	link LinkType
	rtt  time.Duration
	err  error
}

// DialSpeculativeDualLink dials both Wi-Fi and Cellular in parallel and
// returns the winner immediately, plus a channel for the standby (loser)
// connection. The caller owns both connections and must close them.
//
// If the winner fails, the caller can use the standby. If only one link
// has an address, the standby channel is closed immediately.
func DialSpeculativeDualLink(
	ctx context.Context,
	binder SocketBinder,
	ep *DualEndpoint,
	port string,
	preferred LinkType,
) (winner net.Conn, winnerLink LinkType, standbyCh <-chan raceResult, err error) {
	// If no preferred link specified, use striped assignment so parallel
	// connections spread across both links (not just the lower-ping one).
	if preferred == 0 {
		preferred = StripedPreferredLink()
	}
	// NOTE: TrackFlow is NOT deferred here. The caller (ForwardWithMidHandshakeReplay)
	// tracks the flow for the full lifetime of the TCP stream. Deferring here would
	// decrement activeFlows as soon as the dial finished, defeating striping.

	ch := make(chan raceResult, 2)

	// Adaptive head-start: stagger the standby link by ~2x the preferred
	// link's measured RTT (clamped 50-180ms), so the standby only wins if
	// the primary is genuinely stalled.
	headStart := 80 * time.Millisecond
	if rttUs := ewmaRTTMicros[preferred].Load(); rttUs > 0 {
		hs := time.Duration(rttUs*2) * time.Microsecond
		if hs < 50*time.Millisecond {
			hs = 50 * time.Millisecond
		}
		if hs > 180*time.Millisecond {
			hs = 180 * time.Millisecond
		}
		headStart = hs
	}

	dialOne := func(link LinkType, ip string) {
		if ip == "" {
			ch <- raceResult{link: link, err: errNoAddr}
			return
		}
		if link != preferred {
			select {
			case <-ctx.Done():
				ch <- raceResult{link: link, err: ctx.Err()}
				return
			case <-time.After(headStart):
			}
		}
		start := time.Now()
		d := NewBoundDialer(binder, link, 5*time.Second)
		c, dErr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		// NAT64 fallback: if dialing an IPv4 literal on cellular fails
		// (Jio IPv6-only has no IPv4 route), retry via 64:ff9b::/96.
		if dErr != nil && link == LinkCellular {
			if ip4 := net.ParseIP(ip); ip4 != nil && ip4.To4() != nil {
				nat64 := toNAT64(ip4)
				c, dErr = d.DialContext(ctx, "tcp", net.JoinHostPort(nat64, port))
			}
		}
		if dErr == nil && c != nil {
			RecordLinkRTT(link, time.Since(start))
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
		}
		ch <- raceResult{conn: c, link: link, rtt: time.Since(start), err: dErr}
	}

	n := 0
	if ep.WiFiAddr != "" {
		n++
		go dialOne(LinkWiFi, ep.WiFiAddr)
	}
	if ep.CellAddr != "" {
		n++
		go dialOne(LinkCellular, ep.CellAddr)
	}
	if n == 0 {
		closedCh := make(chan raceResult)
		close(closedCh)
		return nil, 0, closedCh, errNoAddr
	}

	first := <-ch
	if first.err == nil {
		// Winner! Return standby channel for the loser
		return first.conn, first.link, ch, nil
	}

	// First failed, wait for second
	if n == 1 {
		closedCh := make(chan raceResult)
		close(closedCh)
		return nil, 0, closedCh, first.err
	}

	second := <-ch
	if second.err == nil {
		closedCh := make(chan raceResult)
		close(closedCh)
		return second.conn, second.link, closedCh, nil
	}

	closedCh := make(chan raceResult)
	close(closedCh)
	return nil, 0, closedCh, first.err
}

// DialRace is a simpler wrapper that returns only the winner and closes the loser.
func DialRace(ctx context.Context, binder SocketBinder, wifiAddr, cellAddr, port string) (net.Conn, LinkType, error) {
	ep := &DualEndpoint{WiFiAddr: wifiAddr, CellAddr: cellAddr}
	winner, link, standbyCh, err := DialSpeculativeDualLink(ctx, binder, ep, port, LinkWiFi)
	if err != nil {
		return nil, 0, err
	}
	// Close the standby in background
	go func() {
		for res := range standbyCh {
			if res.err == nil && res.conn != nil {
				res.conn.Close()
			}
		}
	}()
	return winner, link, nil
}

var errNoAddr = errNoAddrType{}

type errNoAddrType struct{}

func (errNoAddrType) Error() string { return "multipath: no address for link" }
