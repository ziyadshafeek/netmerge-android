package multipath

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

type Racer struct {
	binder    SocketBinder
	resolver  *VIPResolver
	scheduler *Scheduler
}

func NewRacer(binder SocketBinder, resolver *VIPResolver, scheduler *Scheduler) *Racer {
	return &Racer{
		binder:    binder,
		resolver:  resolver,
		scheduler: scheduler,
	}
}

// Scheduler exposes the BDP-aware link scheduler driving dial decisions.
func (r *Racer) Scheduler() *Scheduler {
	return r.scheduler
}

// DialContext intercepts synthetic VIPs (198.18.0.0/15) or domain/IP targets and
// races bound connections across Wi-Fi and Jio 5G according to Scheduler weights.
func (r *Racer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var wifiTarget, cellTarget string
	if ip := net.ParseIP(host); ip != nil {
		if ep, ok := r.resolver.LookupVIP(ip); ok {
			wAddr, cAddr := ep.WaitReady(ctx)
			if wAddr != "" {
				wifiTarget = net.JoinHostPort(wAddr, port)
			}
			if cAddr != "" {
				cellTarget = net.JoinHostPort(cAddr, port)
			}
		} else if ip.To4() != nil {
			wifiTarget = address
			if synth := SynthesizeCarrierNAT64(ip); synth != "" {
				cellTarget = net.JoinHostPort(synth, port)
			} else {
				cellTarget = address
			}
		} else {
			wifiTarget = address
			cellTarget = address
		}
	} else {
		_, ep := r.resolver.GetOrAllocate(ctx, host)
		if ep != nil {
			wAddr, cAddr := ep.WaitReady(ctx)
			if wAddr != "" {
				wifiTarget = net.JoinHostPort(wAddr, port)
			}
			if cAddr != "" {
				cellTarget = net.JoinHostPort(cAddr, port)
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

	primary, secondary, stagger := r.scheduler.SelectLinks(256 * 1024)
	return r.raceTargets(ctx, network, primary, secondary, stagger, wifiTarget, cellTarget)
}

// DialLink opens a metered connection strictly pinned to a single physical link
// (used by parallel HTTP Range chunk workers to saturate both radios simultaneously).
func (r *Racer) DialLink(ctx context.Context, network string, link LinkType, host string, port int) (*MeteredConn, error) {
	portStr := strconv.Itoa(port)
	target := net.JoinHostPort(host, portStr)

	if ip := net.ParseIP(host); ip != nil {
		if ep, ok := r.resolver.LookupVIP(ip); ok {
			wAddr, cAddr := ep.WaitReady(ctx)
			if link == LinkCellular && cAddr != "" {
				target = net.JoinHostPort(cAddr, portStr)
			} else if link == LinkWiFi && wAddr != "" {
				target = net.JoinHostPort(wAddr, portStr)
			}
		} else if link == LinkCellular && ip.To4() != nil {
			if synth := SynthesizeCarrierNAT64(ip); synth != "" {
				target = net.JoinHostPort(synth, portStr)
			}
		}
	} else if r.resolver != nil {
		_, ep := r.resolver.GetOrAllocate(ctx, host)
		if ep != nil {
			wAddr, cAddr := ep.WaitReady(ctx)
			if link == LinkCellular && cAddr != "" {
				target = net.JoinHostPort(cAddr, portStr)
			} else if link == LinkWiFi && wAddr != "" {
				target = net.JoinHostPort(wAddr, portStr)
			}
		}
	}

	return r.dialSingle(ctx, network, link, target)
}

func (r *Racer) raceTargets(
	ctx context.Context,
	network string,
	primary, secondary LinkType,
	stagger time.Duration,
	wifiTarget, cellTarget string,
) (net.Conn, error) {
	type dialResult struct {
		conn *MeteredConn
		err  error
	}

	targetFor := func(l LinkType) string {
		if l == LinkCellular {
			return cellTarget
		}
		return wifiTarget
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan dialResult, 2)

	// Launch primary path immediately.
	go func() {
		c, err := r.dialSingle(raceCtx, network, primary, targetFor(primary))
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
		// Primary failed before stagger expired; fire secondary immediately.
		launchedSecondary = true
		go func() {
			c, err := r.dialSingle(raceCtx, network, secondary, targetFor(secondary))
			resCh <- dialResult{conn: c, err: err}
		}()
	case <-timer.C:
		// Primary still in flight after stagger; launch secondary in parallel.
		launchedSecondary = true
		go func() {
			c, err := r.dialSingle(raceCtx, network, secondary, targetFor(secondary))
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
				cancel() // Cancel the losing in-flight dialer; if it still connects, drain & close it.
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

func (r *Racer) dialSingle(ctx context.Context, network string, link LinkType, target string) (*MeteredConn, error) {
	dialer := NewBoundDialer(r.binder, link, 5*time.Second)
	start := time.Now()
	c, err := dialer.DialContext(ctx, network, target)
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
	ReArmQuickAck(c)
	return NewMeteredConn(c, r.binder, r.scheduler, link), nil
}

// RelayBidirectional splices traffic between local and remote sockets using
// 256 KB pooled buffers to eliminate GC pressure at multi-hundred-Mbps speeds.
func RelayBidirectional(local, remote net.Conn) error {
	errCh := make(chan error, 2)

	copyDir := func(dst, src net.Conn) {
		bufPtr := spliceBufferPool.Get().(*[]byte)
		buf := *bufPtr
		_, err := io.CopyBuffer(dst, src, buf)
		spliceBufferPool.Put(bufPtr)
		if tcp, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		errCh <- err
	}

	go copyDir(remote, local)
	go copyDir(local, remote)

	firstErr := <-errCh
	_ = local.SetDeadline(time.Now().Add(250 * time.Millisecond))
	_ = remote.SetDeadline(time.Now().Add(250 * time.Millisecond))
	secondErr := <-errCh

	_ = local.Close()
	_ = remote.Close()

	if firstErr != nil && !errors.Is(firstErr, io.EOF) {
		return firstErr
	}
	if secondErr != nil && !errors.Is(secondErr, io.EOF) {
		return secondErr
	}
	return nil
}
