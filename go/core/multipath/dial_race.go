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

// DialRace dials the same target across Wi-Fi and Cellular in parallel
// (Happy Eyeballs style) and returns the winner — the first to complete
// the TCP handshake. The loser is closed.
//
// binder binds each socket to its physical link. wifiAddr and cellAddr are
// the per-link destination IPs (from DualEndpoint); either may be empty,
// in which case that link is skipped.
//
// If both dials fail, the first error is returned.
func DialRace(ctx context.Context, binder SocketBinder, wifiAddr, cellAddr, port string) (net.Conn, LinkType, error) {
	ch := make(chan raceResult, 2)

	dialOne := func(link LinkType, ip string) {
		if ip == "" {
			ch <- raceResult{link: link, err: errNoAddr}
			return
		}
		start := time.Now()
		d := NewBoundDialer(binder, link, 5*time.Second)
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		ch <- raceResult{conn: c, link: link, rtt: time.Since(start), err: err}
	}

	n := 0
	if wifiAddr != "" {
		n++
		go dialOne(LinkWiFi, wifiAddr)
	}
	if cellAddr != "" {
		n++
		go dialOne(LinkCellular, cellAddr)
	}
	if n == 0 {
		return nil, 0, errNoAddr
	}

	// Winner takes the connection; close the loser when it arrives.
	first := <-ch
	if first.err == nil {
		go func() {
			for i := 1; i < n; i++ {
				if r := <-ch; r.err == nil && r.conn != nil {
					r.conn.Close()
				}
			}
		}()
		return first.conn, first.link, nil
	}

	// First failed; wait for the second.
	if n == 1 {
		return nil, 0, first.err
	}
	second := <-ch
	if second.err == nil {
		return second.conn, second.link, nil
	}
	return nil, 0, first.err
}

var errNoAddr = errNoAddrType{}

type errNoAddrType struct{}

func (errNoAddrType) Error() string { return "multipath: no address for link" }
