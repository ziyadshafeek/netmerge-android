// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// activeFlows tracks in-flight VIP connections per link for striping.
// When Chrome opens N parallel TCP streams, we alternate the preferred
// link so both Wi-Fi and Cellular carry traffic (not just the lower-ping
// link winning 100% of races).
var activeFlows [3]atomic.Int64 // indexed by LinkType (1=WiFi, 2=Cellular)

// toNAT64 converts an IPv4 address to its RFC 6052 NAT64 form
// (64:ff9b::/96) for use on IPv6-only links (e.g. Jio).
func toNAT64(ip4 net.IP) string {
	ip4 = ip4.To4()
	if ip4 == nil {
		return ""
	}
	return net.IP{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, ip4[0], ip4[1], ip4[2], ip4[3]}.String()
}

// StripedPreferredLink returns the link that should be preferred for the
// next connection, based on fewest active flows (weighted striping).
func StripedPreferredLink() LinkType {
	wifi := activeFlows[LinkWiFi].Load()
	cell := activeFlows[LinkCellular].Load()
	if cell < wifi {
		return LinkCellular
	}
	return LinkWiFi
}

// TrackFlow increments the active flow counter for link, returning a
// function to call when the flow ends.
func TrackFlow(link LinkType) func() {
	activeFlows[link].Add(1)
	return func() { activeFlows[link].Add(-1) }
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

	dialOne := func(link LinkType, ip string) {
		if ip == "" {
			ch <- raceResult{link: link, err: errNoAddr}
			return
		}
		// Give preferred link a head start so it usually wins the race,
		// while the other link serves as a warm standby for failover.
		// 150ms is enough to overcome WiFi-vs-Cellular ping difference
		// without adding noticeable latency to the connection setup.
		if link != preferred {
			select {
			case <-ctx.Done():
				ch <- raceResult{link: link, err: ctx.Err()}
				return
			case <-time.After(150 * time.Millisecond):
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
