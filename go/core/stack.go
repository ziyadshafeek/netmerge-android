package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"netmerge/core/multipath"
)

const (
	nicID        = 1
	tunMTU       = 1500
	dialTimeout  = 10 * time.Second
	failCooldown = 15 * time.Second
)

// udpIdleTimeout is how long a UDP session may go without traffic in
// either direction before it is closed. udpPollInterval is how often the
// relay loops wake up to re-check idleness. Vars (not consts) so tests can
// shrink them.
var (
	udpIdleTimeout  = 60 * time.Second
	udpPollInterval = 10 * time.Second
)

type config struct {
	weights map[string]float64
}

func parseConfig(js string) (config, error) {
	c := config{weights: map[string]float64{}}
	if js == "" {
		return c, nil
	}
	var raw struct {
		Weights map[string]float64 `json:"weights"`
	}
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		return c, err
	}
	for k, v := range raw.Weights {
		if v > 0 {
			c.weights[k] = v
		}
	}
	return c, nil
}

// Engine is the running data plane: netstack + scheduler + probers.
type Engine struct {
	stack     *stack.Stack
	linkEp    stack.LinkEndpoint
	scheduler *Scheduler
	protector Protector

	// Multipath compounding engine (zero-VPS bandwidth bonding)
	mpEngine *multipath.OnPhoneCompoundEngine

	// Loopback HTTP server for 127.0.0.1:18080 compounding
	loopbackSrv *http.Server

	stopCh chan struct{}
	wg     sync.WaitGroup

	udpMu       sync.Mutex
	udpSessions map[string]*udpSession
}

func newEngine(tunFd int, protector Protector, cfg config) (*Engine, error) {
	// The link endpoint reads/writes raw IP packets on the TUN fd.
	// EthernetHeader=false because TUN is L3. New() makes the fd
	// non-blocking but does NOT take ownership: Kotlin still owns tunFd
	// and we must never close it.
	linkEp, err := fdbased.New(&fdbased.Options{
		FDs: []int{tunFd},
		MTU: tunMTU,
	})
	if err != nil {
		return nil, fmt.Errorf("tun link: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			// AllowExternalLoopbackTraffic: apps legitimately talk to
			// 127.0.0.1 (local proxies, dev servers); the TUN is not a
			// real LAN interface, so without this such SYNs are dropped
			// as martians.
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			func(st *stack.Stack) stack.TransportProtocol { return tcp.NewProtocol(st) },
			func(st *stack.Stack) stack.TransportProtocol { return udp.NewProtocol(st) },
		},
	})
	if terr := s.CreateNIC(nicID, linkEp); terr != nil {
		return nil, fmt.Errorf("create nic: %s", terr)
	}
	// Promiscuous so the stack accepts packets for *any* destination IP:
	// we terminate everything the TUN captures, we don't route it.
	if terr := s.SetPromiscuousMode(nicID, true); terr != nil {
		return nil, fmt.Errorf("promiscuous: %s", terr)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// Tune gVisor's TCP stack for high-BDP dual-link (Wi-Fi + 5G) bonding.
	// Default buffers are too small and cap single-connection throughput.
	multipath.ConfigureGVisorTCP(s)

	e := &Engine{
		stack:       s,
		linkEp:      linkEp,
		scheduler:   newScheduler(cfg.weights),
		protector:   protector,
		stopCh:      make(chan struct{}),
		udpSessions: map[string]*udpSession{},
	}
	// Initialize the on-phone compounding engine (VIP resolver, splicer, etc.)
	e.newMultipathEngine()

	// Start the 127.0.0.1:18080 loopback compounding server
	e.startLoopbackServer()

	tcpFwd := tcp.NewForwarder(s, 0, 4096, e.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, e.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	e.wg.Add(1)
	go e.loop()
	return e, nil
}

// loop is the single background goroutine: 1s tick drives weight sampling
// and probe scheduling. One goroutine, no busy loops: battery-sane.
func (e *Engine) loop() {
	defer e.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-t.C:
			e.scheduler.Tick(time.Second)
			for _, j := range e.probeDue() {
				go e.runProbe(j.sl, j.f)
			}
		}
	}
}

func (e *Engine) close() {
	select {
	case <-e.stopCh:
		return
	default:
		close(e.stopCh)
	}
	e.wg.Wait()
	// Drop UDP sessions.
	e.udpMu.Lock()
	for _, us := range e.udpSessions {
		us.close()
	}
	e.udpSessions = map[string]*udpSession{}
	e.udpMu.Unlock()
	e.stack.Close()
	// NOTE: linkEp/tunFd intentionally not closed: Kotlin owns the fd.
}

// familyOf maps a netstack address to its address family.
func familyOf(addr tcpip.Address) Family {
	if addr.Len() == 4 {
		return Fam4
	}
	return Fam6
}

// tcpipToIP converts a netstack address to net.IP.
func tcpipToIP(addr tcpip.Address) net.IP {
	if addr.Len() == 4 {
		b := addr.As4()
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	b := addr.As16()
	out := make(net.IP, 16)
	copy(out, b[:])
	return out
}

// ---- TCP ----

// handleTCP runs for every new inbound TCP connection from the TUN.
// ensureAddr registers addr as a permanent protocol address on the TUN NIC
// so reply packets can be sourced from it. Safe to call concurrently;
// duplicates are ignored.
func (e *Engine) ensureAddr(addr tcpip.Address) {
	proto := header.IPv4ProtocolNumber
	if addr.Len() == 16 {
		proto = header.IPv6ProtocolNumber
	}
	_ = e.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint})
}

func (e *Engine) handleTCP(r *tcp.ForwarderRequest) {
	defer func() { _ = recover() }()
	id := r.ID()
	// Ensure the destination address is registered on the NIC so the
	// stack can source reply packets from it. Promiscuous mode lets the
	// inbound SYN through via a temporary address, but temporary
	// addresses are not eligible as source addresses for the SYN-ACK;
	// promoting to a permanent address fixes the return path.
	// Duplicate adds are harmless (ErrDuplicateAddress is ignored).
	e.ensureAddr(id.LocalAddress)
	host := tcpipToIP(id.LocalAddress).String()
	port := uint16(id.LocalPort)

	// Privacy leak lockdown on the TCP path (DoT bypass, NetBIOS): reject
	// before CreateEndpoint so the stack answers RST and the app falls back
	// to the sharded DoH resolver. (TCP 443 is unaffected: only UDP 443/QUIC
	// is blocked, forcing multi-connection TCP where SNI slicing applies.)
	if multipath.ShouldBlockPrivacyLeak(false, nil, int(port)) {
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	tunConn := gonet.NewTCPConn(&wq, ep)

	// Use the multipath compound engine for full on-phone compounding:
	// - DNS VIP anti-coalescing (already done via DNS interceptor)
	// - Dual-link SYN racing with ClientHello replay for TLS/banking
	// - HalvingSplicer for HTTP range compounding
	// - All with zero TLS interception, zero Root CA
	if e.mpEngine != nil {
		// Look up DualEndpoint for this VIP (or create from literal IP)
		dualEP := e.mpEngine.DNS.LookupVIP(host)
		if dualEP == nil {
			// Direct IP connection (not a VIP): use literal IP on both links
			// The resolver will have resolved it via the background DNS
			dualEP = &multipath.DualEndpoint{
				Domain:   host,
				WiFiAddr: host,
				CellAddr: host,
			}
		}

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			_ = e.mpEngine.HandleGVisorTCPStream(ctx, tunConn, dualEP, port)
		}()
		return
	}

	// Fallback: legacy single-link path (should not happen)
	f := familyOf(id.LocalAddress)
	upstream, slot, err := e.dialTCP(f, host, int(port))
	if err != nil {
		tunConn.Close()
		return
	}
	e.relayTCP(tunConn, upstream, slot, f)
}

// dialTCP connects to host:port through the scheduler, failing over to
// other networks on link-level errors. On success the caller owns the slot
// and must relay or release it.
func (e *Engine) dialTCP(f Family, host string, port int) (net.Conn, *Slot, error) {
	tried := map[string]struct{}{}
	var lastErr error = fmt.Errorf("no usable network")
	for {
		sl := e.scheduler.AcquireFor(f, tried)
		if sl == nil {
			if lastErr == nil {
				lastErr = fmt.Errorf("no usable network")
			}
			return nil, nil, lastErr
		}
		tried[sl.ID] = struct{}{}
		c, err := e.dialBound(sl, f, "tcp", host, port, dialTimeout)
		if err == nil {
			return c, sl, nil
		}
		e.scheduler.ReleaseFor(sl, f)
		lastErr = err
		if isLinkDown(err) {
			e.scheduler.Fail(sl, f, failCooldown)
			continue // try the next network
		}
		return nil, nil, err // destination refused etc: don't flap networks
	}
}

// ---- UDP ----

type udpSession struct {
	key      string
	tunConn  net.PacketConn // *gonet.UDPConn in production; stubbed in tests
	upstream net.Conn
	slot     *Slot
	family   Family
	dstPort  int
	dstHost  string
	lastAct  atomic.Int64 // unix nanos of last datagram either way
	closed   atomic.Bool
	closeCh  chan struct{}
}

func (us *udpSession) touch() { us.lastAct.Store(time.Now().UnixNano()) }
func (us *udpSession) idle() time.Duration {
	return time.Since(time.Unix(0, us.lastAct.Load()))
}
func (us *udpSession) close() {
	if us.closed.CompareAndSwap(false, true) {
		close(us.closeCh)
		us.tunConn.Close()
		us.upstream.Close()
	}
}

// udpKey is the 5-tuple identifying a UDP session.
func udpKey(f Family, id stack.TransportEndpointID) string {
	return "udp/" + tcpipToIP(id.RemoteAddress).String() + ":" +
		strconv.Itoa(int(id.RemotePort)) + "->" + tcpipToIP(id.LocalAddress).String() + ":" +
		strconv.Itoa(int(id.LocalPort))
}

// handleUDP runs for the first datagram of each new 5-tuple. Later
// datagrams are delivered straight to the session's endpoint.
func isSyntheticVIP(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func (e *Engine) handleUDP(r *udp.ForwarderRequest) (handled bool) {
	defer func() { _ = recover() }()
	id := r.ID()
	// See handleTCP: ensure the destination is a usable source address
	// for replies.
	e.ensureAddr(id.LocalAddress)
	f := familyOf(id.LocalAddress)
	dstIP := tcpipToIP(id.LocalAddress)
	dstHost, dstPort := dstIP.String(), int(id.LocalPort)

	// Privacy leak lockdown + QUIC/DoT blocking BEFORE CreateEndpoint so gVisor
	// emits ICMP Port Unreachable and apps fall back in <1ms:
	// - UDP 443 (QUIC): forces multi-connection TCP 443 (SNI slicing + bonding)
	// - 853 (DoT): forces fallback to the sharded DoH VIP resolver
	// - 5353/5355/1900/137-139 (mDNS/LLMNR/SSDP/NetBIOS): blocks LAN identity leaks
	// - STUN/TURN ports: blocks WebRTC IP leaks (falls back to TURN/TCP)
	if multipath.ShouldBlockPrivacyLeak(true, nil, dstPort) || (dstPort != 53 && isSyntheticVIP(dstIP)) {
		return false
	}

	key := udpKey(f, id)

	e.udpMu.Lock()
	if _, dup := e.udpSessions[key]; dup {
		e.udpMu.Unlock()
		return true // racing datagram; the live session owns it
	}
	e.udpMu.Unlock()

	// Pick the network BEFORE dialing: DNS needs the slot's DNS server.
	sl := e.scheduler.AcquireFor(f, nil)
	if sl == nil {
		return false // ICMP port unreachable; nothing can carry it
	}
	if dstPort == 53 {
		dnsFam := f
		if dns := e.dnsServerFor(sl, f); dns != nil {
			dstHost = dns.String() // dns.go: keep DNS on the right link
			// Use the DNS server's actual family, not the VPN-local family.
			// Jio cellular is IPv6-only: passing an IPv6 DNS with Fam4
			// forces "udp4" and kills the dial with EAFNOSUPPORT.
			if dns.To4() == nil {
				dnsFam = Fam6
			} else {
				dnsFam = Fam4
			}
		} else if f == Fam4 {
			// Jio IPv6-only cellular has no IPv4 DNS in LinkProperties;
			// fall back to 8.8.8.8 (reached via NAT64) instead of 10.8.0.1
			dstHost = "8.8.8.8"
			dnsFam = Fam4
		} else {
			dstHost = "2001:4860:4860::8888"
			dnsFam = Fam6
		}
		f = dnsFam
	}

	upstream, err := e.dialBoundUDP(sl, f, dstHost, dstPort)
	if err != nil {
		e.scheduler.ReleaseFor(sl, f)
		if isLinkDown(err) {
			e.scheduler.Fail(sl, f, failCooldown)
		}
		return false
	}

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		upstream.Close()
		e.scheduler.ReleaseFor(sl, f)
		return false
	}
	tunConn := gonet.NewUDPConn(&wq, ep)

	us := &udpSession{
		key: key, tunConn: tunConn, upstream: upstream,
		slot: sl, family: f, dstPort: dstPort, dstHost: dstHost, closeCh: make(chan struct{}),
	}
	us.touch()
	e.udpMu.Lock()
	e.udpSessions[key] = us
	e.udpMu.Unlock()

	clientAddr := &net.UDPAddr{IP: tcpipToIP(id.RemoteAddress), Port: int(id.RemotePort)}
	go e.relayUDP(us, clientAddr)
	return true
}

// relayUDP shuttles datagrams between the TUN side and the upstream socket
// until the session idles out (60s without traffic either way) or errors.
func (e *Engine) relayUDP(us *udpSession, clientAddr *net.UDPAddr) {
	defer func() { _ = recover() }()
	defer e.dropUDPSession(us)

	// Simplified bidirectional relay: io.Copy in both directions.
	// DNS VIP interception happens on the TUN->upstream path before forwarding.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // TUN -> upstream
		defer wg.Done()
		defer us.close() // wake up the upstream->TUN goroutine on exit
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		for {
			us.tunConn.SetReadDeadline(time.Now().Add(udpPollInterval))
			n, _, err := us.tunConn.ReadFrom((*buf)[:cap(*buf)])
			if err != nil {
				if isTimeout(err) && us.idle() < udpIdleTimeout {
					continue
				}
				return
			}
			us.touch()
			us.slot.bytesOut[us.family].Add(int64(n))

			// DNS interception: synthetic VIP response goes straight back.
			// HandleQuery may block on VIP allocation (upstream DNS), so run
			// it in a goroutine with copied bytes — concurrent queries on
			// this socket must never block each other.
			if us.dstPort == 53 && e.mpEngine != nil {
				q := append([]byte(nil), (*buf)[:n]...)
				respCh := make(chan []byte, 1)
				go func() {
					defer func() { _ = recover() }()
					respCh <- e.mpEngine.DNS.HandleQuery(q)
				}()
				select {
				case resp := <-respCh:
					if resp != nil {
						if _, err := us.tunConn.WriteTo(resp, clientAddr); err != nil {
							return
						}
						continue // Don't forward to upstream
					}
				case <-time.After(2 * time.Second):
					// HandleQuery stalled; fall through to upstream DNS
				}
			}

			// Note: QUIC (UDP/443) is blocked upfront in handleUDP with ICMP
			// Port Unreachable, so no QUICGuard eviction is needed here.

			if _, err := us.upstream.Write((*buf)[:n]); err != nil {
				return
			}
		}
	}()
	go func() { // upstream -> TUN
		defer wg.Done()
		defer us.close() // wake up the TUN->upstream goroutine on exit
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		for {
			us.upstream.SetReadDeadline(time.Now().Add(udpPollInterval))
			n, err := us.upstream.Read((*buf)[:cap(*buf)])
			if err != nil {
				if isTimeout(err) && us.idle() < udpIdleTimeout {
					continue
				}
				return
			}
			us.touch()
			us.slot.bytesIn[us.family].Add(int64(n))
			if _, err := us.tunConn.WriteTo((*buf)[:n], clientAddr); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func (e *Engine) dropUDPSession(us *udpSession) {
	e.udpMu.Lock()
	if cur, ok := e.udpSessions[us.key]; ok && cur == us {
		delete(e.udpSessions, us.key)
	}
	e.udpMu.Unlock()
	us.close()
	e.scheduler.ReleaseFor(us.slot, us.family)
}

// ---- relay ----

var bufPool = sync.Pool{New: func() any { b := make([]byte, 128<<10); return &b }}

// relayTCP copies both directions until both sides finish, counting bytes
// per network/family, then closes both conns and releases the slot.
// Half-close is honoured so request/response protocols that shut down
// their write side still receive the reply.
func (e *Engine) relayTCP(client, upstream net.Conn, sl *Slot, f Family) {
	var wg sync.WaitGroup
	var once sync.Once
	release := func() {
		once.Do(func() {
			if sl != nil {
				e.scheduler.ReleaseFor(sl, f)
			}
		})
	}
	// For VIP flows (sl == nil), use dummy counters
	var bytesOut, bytesIn atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		if sl != nil {
			pump(upstream, client, &sl.bytesOut[f])
		} else {
			pump(upstream, client, &bytesOut)
		}
		release()
	}()
	if sl != nil {
		pump(client, upstream, &sl.bytesIn[f])
	} else {
		pump(client, upstream, &bytesIn)
	}
	release()
	wg.Wait()
	client.Close()
	upstream.Close()
}

func pump(dst, src net.Conn, counter *atomic.Int64) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			counter.Add(int64(n))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				dst.Close()
				src.Close()
				return
			}
		}
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			closeWrite(dst, src, err)
			return
		}
	}
}

func closeWrite(dst, src net.Conn, rerr error) {
	// EOF (io.EOF or a closed connection): half-close the destination so
	// the other direction can still deliver its reply.
	if rerr != nil && (isEOF(rerr)) {
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
	}
	dst.Close()
	src.Close()
}

func isEOF(err error) bool {
	if err == nil {
		return false
	}
	// gonet returns io.EOF; raw conns surface EPIPE/ECONNRESET when the
	// peer is gone, which is also "done reading".
	return errors.Is(err, io.EOF) ||
		err == syscall.EPIPE || err == syscall.ECONNRESET
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
