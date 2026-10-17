// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

import (
	"context"
	"net"
	"time"
)

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
	ch := make(chan raceResult, 2)

	dialOne := func(link LinkType, ip string) {
		if ip == "" {
			ch <- raceResult{link: link, err: errNoAddr}
			return
		}
		// Give preferred link a tiny head start
		if link != preferred {
			select {
			case <-ctx.Done():
				ch <- raceResult{link: link, err: ctx.Err()}
				return
			case <-time.After(8 * time.Millisecond):
			}
		}
		start := time.Now()
		d := NewBoundDialer(binder, link, 5*time.Second)
		c, dErr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		// NAT64 fallback: if dialing an IPv4 literal on cellular fails
		// (Jio IPv6-only has no IPv4 route), retry via 64:ff9b::/96.
		if dErr != nil && link == LinkCellular {
			if ip4 := net.ParseIP(ip); ip4 != nil && ip4.To4() != nil {
				nat64 := "64:ff9b::" + ip4.To4().String()
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
