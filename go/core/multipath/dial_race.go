package multipath

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	activeFlows   [3]atomic.Int64 // total open streams
	rollingBytes  [3]atomic.Int64 // decayed rolling byte load (updated every read/write)
	peakRateBps   [3]atomic.Int64 // observed peak bytes/sec per link
	lastDecayNano atomic.Int64    // timestamp of last 200ms rolling byte decay
	stalledUntil  [3]atomic.Int64 // cooldown timestamp if link failed handshake
	rrCounter     atomic.Uint64
)

// RecordLinkBytes is called on every read/write chunk to track live instantaneous
// load on each radio. Idle keep-alive sockets contribute 0 bytes, so they never
// fool the scheduler!
func RecordLinkBytes(link LinkType, n int64) {
	if (link != LinkWiFi && link != LinkCellular) || n <= 0 {
		return
	}
	now := time.Now().UnixNano()
	last := lastDecayNano.Load()
	if last == 0 {
		lastDecayNano.CompareAndSwap(0, now)
	} else if now-last > int64(200*time.Millisecond) {
		if lastDecayNano.CompareAndSwap(last, now) {
			for _, l := range []LinkType{LinkWiFi, LinkCellular} {
				cur := rollingBytes[l].Load()
				rate := cur * 5 // bytes per sec (200ms window * 5)
				if rate > peakRateBps[l].Load() {
					peakRateBps[l].Store(rate)
				} else {
					peakRateBps[l].Store((peakRateBps[l].Load()*15 + rate) / 16)
				}
				// Halve rolling bytes every 200ms for smooth exponential window
				rollingBytes[l].Store(cur / 2)
			}
		}
	}
	rollingBytes[link].Add(n)
}

func MarkLinkStalled(link LinkType, d time.Duration) {
	if link == LinkWiFi || link == LinkCellular {
		stalledUntil[link].Store(time.Now().Add(d).UnixNano())
	}
}

// StripedPreferredLink picks the link with the most spare capacity right now
// using rolling active byte volume (NOT idle socket count).
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

	wBytes := rollingBytes[LinkWiFi].Load()
	cBytes := rollingBytes[LinkCellular].Load()

	// 1. If neither link (or only one link) is actively transferring bytes right now,
	// strictly alternate or pick the idle link so both radios engage immediately!
	if wBytes < 8192 && cBytes < 8192 {
		if rrCounter.Add(1)%2 == 0 {
			return LinkCellular
		}
		return LinkWiFi
	}
	if wBytes < 8192 {
		return LinkWiFi
	}
	if cBytes < 8192 {
		return LinkCellular
	}

	// 2. Both links are actively pumping bytes! Balance by instantaneous utilization
	// relative to observed peak capacity (clamped so neither link is ever starved).
	wPeak := float64(peakRateBps[LinkWiFi].Load())
	cPeak := float64(peakRateBps[LinkCellular].Load())
	if wPeak < 256*1024 || cPeak < 256*1024 {
		// Uncalibrated peaks: pick the link carrying fewer live bytes right now
		if cBytes < wBytes {
			return LinkCellular
		}
		return LinkWiFi
	}

	// Utilization ratio = currentWindowBytes / peakCapacity
	wUtil := float64(wBytes) / wPeak
	cUtil := float64(cBytes) / cPeak
	if cUtil < wUtil {
		return LinkCellular
	}
	return LinkWiFi
}

func TrackFlow(link LinkType) func() {
	activeFlows[link].Add(1)
	if fn, ok := flowHook.Load().(func(LinkType, int64)); ok && fn != nil {
		fn(link, 1)
	}
	return func() {
		activeFlows[link].Add(-1)
		if fn, ok := flowHook.Load().(func(LinkType, int64)); ok && fn != nil {
			fn(link, -1)
		}
	}
}

// Pre-Warmed Socket Pool: stores unused standby sockets (0 bytes written)
// so the next parallel stream on the other radio connects in 0.00ms!
type warmConn struct {
	conn      net.Conn
	createdAt time.Time
}

// maxWarmSocketAge bounds how long a pre-warmed socket may sit idle before it
// must be re-verified or discarded.
const maxWarmSocketAge = 15 * time.Second

// isSocketAlive performs a non-blocking MSG_PEEK to detect sockets the edge
// server already closed (FIN), so warmPool never hands out dead connections.
func isSocketAlive(conn net.Conn) bool {
	for {
		mc, ok := conn.(*MorphingConn)
		if !ok {
			break
		}
		conn = mc.Conn
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return false
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return false
	}
	alive := true
	if err := rawConn.Read(func(fd uintptr) bool {
		var buf [1]byte
		n, _, recvErr := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		if n == 0 && recvErr == nil {
			alive = false // remote peer sent FIN (EOF)
		} else if recvErr != nil && recvErr != syscall.EAGAIN && recvErr != syscall.EWOULDBLOCK {
			alive = false
		}
		return true
	}); err != nil {
		return false
	}
	return alive
}

var (
	warmMu   sync.Mutex
	warmPool = make(map[string][]warmConn)
)

func warmKey(link LinkType, ip, port string) string {
	return string(rune('0'+link)) + "|" + ip + "|" + port
}

func popWarmConn(link LinkType, ip, port string) net.Conn {
	k := warmKey(link, ip, port)
	now := time.Now()
	warmMu.Lock()
	defer warmMu.Unlock()
	list := warmPool[k]
	for len(list) > 0 {
		wc := list[len(list)-1]
		list = list[:len(list)-1]
		if now.Sub(wc.createdAt) > maxWarmSocketAge {
			wc.conn.Close()
			continue
		}
		if !isSocketAlive(wc.conn) {
			wc.conn.Close()
			continue
		}
		warmPool[k] = list
		return wc.conn
	}
	delete(warmPool, k)
	return nil
}

func PutWarmConn(link LinkType, ip, port string, c net.Conn) {
	if c == nil || ip == "" {
		return
	}
	k := warmKey(link, ip, port)
	warmMu.Lock()
	list := warmPool[k]
	if len(list) >= 4 {
		warmMu.Unlock()
		c.Close()
		return
	}
	warmPool[k] = append(list, warmConn{conn: c, createdAt: time.Now()})
	warmMu.Unlock()
}

// PurgeWarmPool closes and removes all pre-warmed sockets (called when
// cellular switches 5G <-> 4G or a link's IP changes).
func PurgeWarmPool() {
	warmMu.Lock()
	defer warmMu.Unlock()
	for k, list := range warmPool {
		for _, wc := range list {
			_ = wc.conn.Close()
		}
		delete(warmPool, k)
	}
}

var flowHook atomic.Value // func(LinkType, int64)

func SetFlowHook(fn func(LinkType, int64)) {
	flowHook.Store(fn)
}

func toNAT64(ip4 net.IP) string {
	ip4 = ip4.To4()
	if ip4 == nil {
		return ""
	}
	return net.IP{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, ip4[0], ip4[1], ip4[2], ip4[3]}.String()
}

type raceResult struct {
	conn net.Conn
	link LinkType
	ip   string
	rtt  time.Duration
	err  error
}

// DialLinkConn dials a single link (with automatic NAT64 synthesis on Cellular)
// and sets TCP_NODELAY.
var cellDualExitToggle atomic.Uint64

// DialLinkConn dials a single link with automatic Jio 4G/5G IPv6 <-> 464XLAT IPv4
// failover so a 5G -> 4G handover never stalls on dead sockets or unrouted NAT64.
// Every returned connection is wrapped in MorphingConn for L4 stream morphing.
func DialLinkConn(ctx context.Context, binder SocketBinder, link LinkType, ip, fallbackIPv4, port string) (net.Conn, error) {
	if c := popWarmConn(link, ip, port); c != nil {
		return WrapMorphingConn(c, link), nil
	}
	d := NewBoundDialer(binder, link, 3500*time.Millisecond)
	if egress := GlobalPrivacy.EgressForLink(link); egress != nil && egress.Address != "" {
		c, err := DialThroughPrivacyEgress(ctx, d, egress, "tcp", net.JoinHostPort(ip, port))
		if err == nil && c != nil {
			armKeepAlive(c)
			return WrapMorphingConn(c, link), nil
		}
		return nil, err
	}
	// Only stripe across Carrier NAT64 if the NAT64 prefix has been verified
	// reachable on this cellular network (prevents 1100ms timeouts on Jio 4G
	// where 64:ff9b::/96 is unrouted and 464XLAT/clatd handles IPv4).
	if link == LinkCellular && IsNAT64PrefixVerified() {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil && cellDualExitToggle.Add(1)%2 == 0 {
			if nat64 := SynthesizeCarrierNAT64(parsed); nat64 != "" {
				natCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
				c, err := d.DialContext(natCtx, "tcp", net.JoinHostPort(nat64, port))
				cancel()
				if err == nil && c != nil {
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetNoDelay(true)
					}
					armKeepAlive(c)
					return WrapMorphingConn(c, link), nil
				}
			}
		}
	}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil && link == LinkCellular {
		// Evict any stale 5G sockets cached in warmPool when a cellular dial fails.
		PurgeWarmPool()
		parsedIP := net.ParseIP(ip)
		// 1. If primary cellular target was IPv6 and failed (common during Jio
		// 5G -> 4G switch), immediately try raw IPv4 via Android 464XLAT (clatd)!
		if (parsedIP == nil || parsedIP.To4() == nil) && fallbackIPv4 != "" {
			if fb4 := net.ParseIP(fallbackIPv4); fb4 != nil && fb4.To4() != nil {
				c, err = d.DialContext(ctx, "tcp", net.JoinHostPort(fb4.String(), port))
			}
		}
		// 2. If raw IPv4 also failed (CLAT still warming up), try synthesized NAT64.
		if err != nil && IsNAT64PrefixVerified() {
			targetIP4 := parsedIP
			if targetIP4 == nil || targetIP4.To4() == nil {
				targetIP4 = net.ParseIP(fallbackIPv4)
			}
			if targetIP4 != nil && targetIP4.To4() != nil {
				if nat64 := SynthesizeCarrierNAT64(targetIP4); nat64 != "" {
					c, err = d.DialContext(ctx, "tcp", net.JoinHostPort(nat64, port))
				}
			}
		}
	}
	if err == nil && c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		armKeepAlive(c)
		return WrapMorphingConn(c, link), nil
	}
	return c, err
}

// DialSpeculativeDualLink dials Wi-Fi and Cellular for a new flow. When stagger > 0
// and a preferred link is assigned, the NON-preferred dial is delayed by stagger so the
// preferred link (usually Cellular, which needs 260-340ms for 5G NR RRC wakeup + handshake)
// cannot be hijacked by Wi-Fi's shorter RTT. If the preferred dial fails fast, the delayed
// dial starts immediately (failover is never slower than the failure). The preferred link
// also keeps its 45ms grace window when both dial immediately (stagger == 0).
func DialSpeculativeDualLink(
	ctx context.Context,
	binder SocketBinder,
	ep *DualEndpoint,
	port string,
	preferred LinkType,
	stagger time.Duration,
) (winner net.Conn, winnerLink LinkType, standbyCh <-chan raceResult, err error) {
	if preferred == 0 {
		preferred = StripedPreferredLink()
	}

	// Wait for the endpoint to be ready, then rotate across all DNS-verified
	// edge IPs so consecutive flows spread over the CDN's full edge set.
	_, _ = ep.WaitReady(ctx)
	wifiAddr, cellAddr := ep.NextAddrs()
	ep.mu.RLock()
	cellRawV4 := ep.CellRawV4
	ep.mu.RUnlock()
	if cellRawV4 == "" {
		if parsedW := net.ParseIP(wifiAddr); parsedW != nil && parsedW.To4() != nil {
			cellRawV4 = wifiAddr
		}
	}
	savedWiFi, savedCell := wifiAddr, cellAddr
	// STRICT single-radio check: the resolver mirrors the working radio's IP
	// into the dead radio's field (and the dial fallback routes it out the
	// default network anyway), so a non-empty addr does NOT prove the radio is
	// up. Clear addrs whose radio has no live Network ref — otherwise we'd
	// stagger (up to 340ms) against a dead radio and poison worker counts.
	if wifiAddr != "" && binder != nil && !binder.CanBindLink(int(LinkWiFi)) {
		wifiAddr = ""
	}
	if cellAddr != "" && binder != nil && !binder.CanBindLink(int(LinkCellular)) {
		cellAddr = ""
	}
	// CRITICAL JIO 5G -> 4G HANDOVER FIX:
	// During a 5G -> 4G RAT switch on cellular-only mode, Android briefly drops
	// the 5G Network callback (onLost) before registering the 4G Network ref,
	// making CanBindLink false for BOTH links. Never return errNoAddr here:
	// restore the cellular address so BindAndProtect's Protect(fd) fallback
	// routes the socket over Android's active 4G default network!
	if wifiAddr == "" && cellAddr == "" {
		if savedCell != "" {
			cellAddr = savedCell
			preferred = LinkCellular
		} else if savedWiFi != "" {
			wifiAddr = savedWiFi
			preferred = LinkWiFi
		}
	}
	ch := make(chan raceResult, 2)

	// Closed when the preferred link's dial FAILS, so a staggered non-preferred
	// dial can start failover immediately instead of waiting out the stagger.
	prefFailed := make(chan struct{})
	var prefFailedOnce sync.Once

	n := 0
	if wifiAddr != "" {
		n++
	}
	if cellAddr != "" {
		n++
	}
	// Only stagger when both radios are actually dialing; with a single link the
	// delay would just add latency for nothing.
	doStagger := stagger > 0 && preferred != 0 && n == 2

	dialOne := func(link LinkType, ip, otherIP string) {
		if ip == "" {
			if link == preferred {
				prefFailedOnce.Do(func() { close(prefFailed) })
			}
			ch <- raceResult{link: link, err: errNoAddr}
			return
		}
		if doStagger && link != preferred {
			select {
			case <-ctx.Done():
				ch <- raceResult{link: link, err: ctx.Err()}
				return
			case <-prefFailed:
				// Preferred link failed fast; start failover now.
			case <-time.After(stagger):
			}
		}
		start := time.Now()
		c, dErr := DialLinkConn(ctx, binder, link, ip, otherIP, port)
		if dErr != nil && link == preferred {
			prefFailedOnce.Do(func() { close(prefFailed) })
		}
		ch <- raceResult{conn: c, link: link, ip: ip, rtt: time.Since(start), err: dErr}
	}

	n = 0
	var wg sync.WaitGroup
	if wifiAddr != "" {
		n++
		wg.Add(1)
		go func() { defer wg.Done(); dialOne(LinkWiFi, wifiAddr, cellAddr) }()
	}
	if cellAddr != "" {
		n++
		// Always pass cellRawV4 as fallbackIPv4 even when wifiAddr is "" (Wi-Fi off)!
		cellFallback := cellRawV4
		if cellFallback == "" {
			cellFallback = wifiAddr
		}
		wg.Add(1)
		go func() { defer wg.Done(); dialOne(LinkCellular, cellAddr, cellFallback) }()
	}
	if n == 0 {
		closedCh := make(chan raceResult)
		close(closedCh)
		return nil, 0, closedCh, errNoAddr
	}
	// Every standbyCh is closed exactly once all racers finish, so consumers
	// doing `for res := range standbyCh` never leak a blocked goroutine.
	go func() { wg.Wait(); close(ch) }()

	first := <-ch
	if first.err == nil {
		// If the first to finish IS our preferred link (or only 1 link was dialed), return immediately!
		if first.link == preferred || n == 1 {
			return first.conn, first.link, ch, nil
		}
		// Non-preferred link finished first (e.g. Wi-Fi beat 5G by 20ms, but scheduler wants 5G).
		// Wait up to 45ms for preferred link (5G) to finish so 5G gets its scheduled share!
		select {
		case second := <-ch:
			if second.err == nil {
				// Preferred link connected! Put the non-preferred socket into ch as standby
				outCh := make(chan raceResult, 1)
				outCh <- first
				close(outCh)
				return second.conn, second.link, outCh, nil
			}
			// Preferred link failed; use first
			closedCh := make(chan raceResult)
			close(closedCh)
			return first.conn, first.link, closedCh, nil
		case <-time.After(45 * time.Millisecond):
			// Preferred link is still connecting; wait up to another 60ms if preferred link is idle
			if rollingBytes[preferred].Load() < 32*1024 {
				select {
				case second := <-ch:
					if second.err == nil {
						outCh := make(chan raceResult, 1)
						outCh <- first
						close(outCh)
						return second.conn, second.link, outCh, nil
					}
					closedCh := make(chan raceResult)
					close(closedCh)
					return first.conn, first.link, closedCh, nil
				case <-time.After(60 * time.Millisecond):
				}
			}
			return first.conn, first.link, ch, nil
		}
	}

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

func DialRace(ctx context.Context, binder SocketBinder, wifiAddr, cellAddr, port string) (net.Conn, LinkType, error) {
	ep := &DualEndpoint{WiFiAddr: wifiAddr, CellAddr: cellAddr}
	winner, link, standbyCh, err := DialSpeculativeDualLink(ctx, binder, ep, port, 0, 0)
	if err != nil {
		return nil, 0, err
	}
	go func() {
		for res := range standbyCh {
			if res.err == nil && res.conn != nil {
				PutWarmConn(res.link, res.ip, port, res.conn)
			}
		}
	}()
	return winner, link, nil
}

var errNoAddr = errNoAddrType{}

type errNoAddrType struct{}

func (errNoAddrType) Error() string { return "multipath: no address for link" }
