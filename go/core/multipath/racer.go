package multipath

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Racer struct {
	binder    SocketBinder
	resolver  *VIPResolver
	scheduler *Scheduler
	pacerOnce sync.Once
}

func NewRacer(binder SocketBinder, resolver *VIPResolver, scheduler *Scheduler) *Racer {
	r := &Racer{
		binder:    binder,
		resolver:  resolver,
		scheduler: scheduler,
	}
	r.startCellularKeepAwake()
	return r
}

// startCellularKeepAwake prevents the 5G NR modem from dropping into deep RRC_IDLE
// sleep when Wi-Fi is carrying long-lived flows, keeping 5G carrier aggregation ready.
func (r *Racer) startCellularKeepAwake() {
	r.pacerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(6 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				wStats := r.scheduler.Stats(LinkWiFi)
				cStats := r.scheduler.Stats(LinkCellular)
				if wStats.ActiveFlows > 0 && cStats.ActiveFlows == 0 {
					ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
					if r.resolver != nil {
						_ = r.resolver.queryUDPOnLink(ctx, "cloudflare.com", 28, LinkCellular)
					}
					cancel()
				}
			}
		}()
	})
}

// resolveLinkTargets resolves optimal per-link addresses and a Cellular fallback
// address (so Cellular can seamlessly retry NAT64 IPv6 <-> raw IPv4 on connect).
func (r *Racer) resolveLinkTargets(ctx context.Context, address string) (wifiTarget, cellTarget, cellFallback string, err error) {
	host, port, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return "", "", "", splitErr
	}

	buildCellPair := func(primaryAddr, rawV4 string) (string, string) {
		if ip := net.ParseIP(primaryAddr); ip != nil {
			if ip.To4() != nil {
				// Primary is IPv4: provide raw IPv4 and NAT64 IPv6 fallback.
				if synth := SynthesizeCarrierNAT64(ip); synth != "" {
					return net.JoinHostPort(primaryAddr, port), net.JoinHostPort(synth, port)
				}
				return net.JoinHostPort(primaryAddr, port), ""
			}
			// Primary is IPv6: provide IPv6 first and raw IPv4 (CLAT) as fallback.
			if rawV4 != "" {
				return net.JoinHostPort(primaryAddr, port), net.JoinHostPort(rawV4, port)
			}
			return net.JoinHostPort(primaryAddr, port), ""
		}
		return net.JoinHostPort(primaryAddr, port), ""
	}

	if ip := net.ParseIP(host); ip != nil {
		if r.resolver != nil {
			if ep, ok := r.resolver.LookupVIP(ip); ok {
				wAddr, cAddr := ep.WaitReady(ctx)
				ep.mu.RLock()
				rawV4 := ep.CellRawV4
				ep.mu.RUnlock()
				if wAddr != "" {
					wifiTarget = net.JoinHostPort(wAddr, port)
				}
				if cAddr != "" {
					cellTarget, cellFallback = buildCellPair(cAddr, rawV4)
				}
			}
		}
		if wifiTarget == "" && cellTarget == "" {
			wifiTarget = address
			if ip.To4() != nil {
				cellTarget, cellFallback = buildCellPair(host, host)
			} else {
				cellTarget = address
			}
		}
	} else if r.resolver != nil {
		_, ep := r.resolver.GetOrAllocate(ctx, host)
		if ep != nil {
			wAddr, cAddr := ep.WaitReady(ctx)
			ep.mu.RLock()
			rawV4 := ep.CellRawV4
			ep.mu.RUnlock()
			if wAddr != "" {
				wifiTarget = net.JoinHostPort(wAddr, port)
			}
			if cAddr != "" {
				cellTarget, cellFallback = buildCellPair(cAddr, rawV4)
			}
		}
	}

	if wifiTarget == "" && cellTarget == "" {
		wifiTarget = address
		cellTarget = address
	} else if wifiTarget == "" {
		wifiTarget = cellTarget
	} else if cellTarget == "" {
		cellTarget = wifiTarget
	}
	return wifiTarget, cellTarget, cellFallback, nil
}

// DialContext dispatches connections across Wi-Fi and Cellular according to
// the Scheduler's active flow-ratio controller and deficit water-filling weights.
func (r *Racer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	wifiTarget, cellTarget, cellFallback, err := r.resolveLinkTargets(ctx, address)
	if err != nil {
		return nil, err
	}

	primary, secondary, stagger := r.scheduler.SelectLinks(256 * 1024)
	return r.raceTargets(ctx, network, primary, secondary, stagger, wifiTarget, cellTarget, cellFallback)
}

// DialLink opens a metered connection strictly pinned to a single physical link.
func (r *Racer) DialLink(ctx context.Context, network string, link LinkType, host string, port int) (*MeteredConn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	wifiTarget, cellTarget, cellFallback, err := r.resolveLinkTargets(ctx, address)
	if err != nil {
		return nil, err
	}
	if link == LinkCellular {
		return r.dialSingleWithFallback(ctx, network, LinkCellular, cellTarget, cellFallback)
	}
	return r.dialSingleWithFallback(ctx, network, LinkWiFi, wifiTarget, "")
}

func (r *Racer) raceTargets(
	ctx context.Context,
	network string,
	primary, secondary LinkType,
	stagger time.Duration,
	wifiTarget, cellTarget, cellFallback string,
) (net.Conn, error) {
	type dialResult struct {
		conn *MeteredConn
		err  error
	}

	targetFor := func(l LinkType) (string, string) {
		if l == LinkCellular {
			return cellTarget, cellFallback
		}
		return wifiTarget, ""
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan dialResult, 2)

	// Launch primary assigned link immediately.
	go func() {
		t1, fb1 := targetFor(primary)
		c, err := r.dialSingleWithFallback(raceCtx, network, primary, t1, fb1)
		resCh <- dialResult{conn: c, err: err}
	}()

	timer := time.NewTimer(stagger)
	defer timer.Stop()

	var firstErr error
	launchedSecondary := false

	select {
	case res := <-resCh:
		if res.err == nil {
			return res.conn, nil
		}
		firstErr = res.err
		launchedSecondary = true
		go func() {
			t2, fb2 := targetFor(secondary)
			c, err := r.dialSingleWithFallback(raceCtx, network, secondary, t2, fb2)
			resCh <- dialResult{conn: c, err: err}
		}()
	case <-timer.C:
		launchedSecondary = true
		go func() {
			t2, fb2 := targetFor(secondary)
			c, err := r.dialSingleWithFallback(raceCtx, network, secondary, t2, fb2)
			resCh <- dialResult{conn: c, err: err}
		}()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	remaining := 2
	if firstErr != nil {
		remaining = 1
	}

	for i := 0; i < remaining; i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				cancel()
				if i == 0 && remaining == 2 && launchedSecondary {
					go func() {
						if late := <-resCh; late.conn != nil {
							_ = late.conn.Close()
						}
					}()
				}
				return res.conn, nil
			}
			if firstErr == nil {
				firstErr = res.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("multipath: all links failed to connect")
}

// dialSingleWithFallback dials `target` on `link` (routing through the link's
// configured Privacy Egress if enabled), and if a direct Cellular address-family
// mismatch occurs (IPv4 vs NAT64 IPv6), immediately tries `fallbackTarget`.
func (r *Racer) dialSingleWithFallback(
	ctx context.Context,
	network string,
	link LinkType,
	target, fallbackTarget string,
) (*MeteredConn, error) {
	dialer := NewBoundDialer(r.binder, link, 5*time.Second)
	privacyEgress := GlobalPrivacy.EgressForLink(link)

	start := time.Now()
	c, err := DialThroughPrivacyEgress(ctx, dialer, privacyEgress, network, target)
	if err != nil && fallbackTarget != "" && fallbackTarget != target && ctx.Err() == nil {
		start = time.Now()
		c, err = DialThroughPrivacyEgress(ctx, dialer, privacyEgress, network, fallbackTarget)
	}
	if err != nil {
		if ctx.Err() == nil {
			r.scheduler.RecordFailure(link)
		}
		return nil, err
	}

	rtt := time.Since(start)
	r.scheduler.RecordRTT(link, rtt)
	r.scheduler.RecordSuccess(link)
	r.scheduler.AcquireFlow(link)
	armKeepAlive(c)
	ReArmQuickAck(c)
	return NewMeteredConn(c, r.binder, r.scheduler, link), nil
}

// RelayBidirectional splices traffic between local and remote sockets using
// 256 KB pooled buffers to eliminate GC pressure at multi-hundred-Mbps speeds.
// A normal EOF on the upload side (e.g. the HTTP request is fully sent while the
// download runs for minutes) does NOT kill the download direction: deadlines are
// only forced on real socket errors or when the server side finishes.
func RelayBidirectional(local, remote net.Conn) error {
	type copyRes struct {
		dir string
		err error
	}
	resCh := make(chan copyRes, 2)

	copyDir := func(dir string, dst, src net.Conn) {
		bufPtr := spliceBufferPool.Get().(*[]byte)
		buf := *bufPtr
		_, err := io.CopyBuffer(dst, src, buf)
		spliceBufferPool.Put(bufPtr)
		if tcp, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		resCh <- copyRes{dir: dir, err: err}
	}

	go copyDir("tx", remote, local)
	go copyDir("rx", local, remote)

	first := <-resCh
	// Only force-abort the other direction immediately if an actual socket error
	// occurred, or if the server ("rx") finished sending the response.
	if first.err != nil || first.dir == "rx" {
		_ = local.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_ = remote.SetDeadline(time.Now().Add(500 * time.Millisecond))
	}
	second := <-resCh

	_ = local.Close()
	_ = remote.Close()

	if first.err != nil && !errors.Is(first.err, io.EOF) {
		return first.err
	}
	if second.err != nil && !errors.Is(second.err, io.EOF) {
		return second.err
	}
	return nil
}
