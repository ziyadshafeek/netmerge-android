package multipath

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type LinkType int

const (
	LinkWiFi     LinkType = 1
	LinkCellular LinkType = 2
)

const (
	// 4 MB per-socket kernel buffers to sustain high-BDP 5G + Wi-Fi aggregation.
	socketBufSize = 4 * 1024 * 1024

	// Linux/Android TCP socket options for low-latency congestion window ramp-up.
	tcpQuickAck   = 0xc  // TCP_QUICKACK
	tcpWindowClmp = 0xa  // TCP_WINDOW_CLAMP
	ipTosDSCP     = 0x28 // Assured Forwarding AF11 / Low-Latency Throughput
	ipv6TClass    = 0x43 // IPV6_TCLASS
	spliceBufSize = 256 * 1024
)

// SocketBinder binds raw socket descriptors to physical Android Networks (Wi-Fi / Cellular)
// and reports real-time per-link byte telemetry.
type SocketBinder interface {
	BindAndProtect(fd int64, networkType int) bool
	// CanBindLink is the STRICT link-liveness probe: it reports whether the
	// radio currently has a live Network ref, WITHOUT the Protect-fallback
	// that BindAndProtect applies for cold-start null windows. Used to decide
	// single- vs dual-radio behavior (stagger, worker counts).
	CanBindLink(networkType int) bool
	OnBytes(networkType int, rxBytes int64, txBytes int64)
}

var spliceBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, spliceBufSize)
		return &buf
	},
}

// DialBoundContext dials through a bound dialer, forcing the "tcp4" network
// for IPv4 targets. Go's "tcp" with an IPv4 literal already selects AF_INET,
// but making it explicit guarantees the kernel never applies AF_INET6
// dual-stack MSS math (the IPv6-vs-IPv4 20-byte header delta) to an IPv4
// connection — the mechanism behind the JA4T "..._1200_7" tunnel flag.
func DialBoundContext(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && network == "tcp" {
			network = "tcp4"
		}
	}
	return dialer.DialContext(ctx, network, address)
}

// NewBoundDialer creates a net.Dialer strictly pinned to the target physical interface
// with herd-conformant Android Linux kernel socket parameters (zero JA4T anomalies).
func NewBoundDialer(binder SocketBinder, link LinkType, timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) {
				if binder != nil && !binder.BindAndProtect(int64(fd), int(link)) {
					bindErr = errors.New("multipath: failed to bind and protect socket")
					return
				}
				rawFD := int(fd)
				for _, sz := range []int{socketBufSize, 2 * 1024 * 1024, 1024 * 1024} {
					if syscall.SetsockoptInt(rawFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sz) == nil {
						break
					}
				}
				for _, sz := range []int{socketBufSize, 2 * 1024 * 1024, 1024 * 1024} {
					if syscall.SetsockoptInt(rawFD, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sz) == nil {
						break
					}
				}
				// Stock Android kernel herd conformity: default Best-Effort TOS (0x00).
				// NEVER touch TCP_MAXSEG here: the kernel must advertise the
				// genuine hardware interface MSS for wlan0 / rmnet_data*, or
				// BrowserLeaks-style TCP/IP fingerprinting flags MTU:1240 /
				// Link Type:GIF (VPN tunnel detection via JA4T MSS delta).
				_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_IP, syscall.IP_TOS, 0x00)
				_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_IPV6, ipv6TClass, 0x00)
				if network == "tcp" || network == "tcp4" || network == "tcp6" {
					_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
					_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_TCP, tcpQuickAck, 1)
				}
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
}

// ReArmQuickAck re-enables TCP_QUICKACK on a live TCP connection so delayed ACKs
// never throttle 5G NR or Wi-Fi congestion window growth during bulk transfers.
func ReArmQuickAck(conn net.Conn) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpQuickAck, 1)
	})
}

// armKeepAlive enables TCP keepalive with a 30s period so carrier NATs don't
// silently drop idle keep-alive sockets mid-download (which previously surfaced
// as mysterious mid-transfer stalls/aborts).
func armKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// MeteredConn wraps a net.Conn to report exact RX/TX byte counts to SocketBinder
// and Scheduler without locks on the hot path, while applying first-packet TLS SNI
// fragmentation for DPI privacy.
type MeteredConn struct {
	net.Conn
	binder      SocketBinder
	sched       *Scheduler
	link        LinkType
	rxTotal     atomic.Int64
	txTotal     atomic.Int64
	firstWrite  atomic.Bool
	fragmentTLS bool
	closeOnce   sync.Once
}

func NewMeteredConn(c net.Conn, binder SocketBinder, sched *Scheduler, link LinkType) *MeteredConn {
	mc := &MeteredConn{
		Conn:        c,
		binder:      binder,
		sched:       sched,
		link:        link,
		fragmentTLS: GlobalPrivacy.TLSFragmentationEnabled(),
	}
	mc.firstWrite.Store(true)
	return mc
}

func (m *MeteredConn) Link() LinkType {
	return m.link
}

func (m *MeteredConn) Read(b []byte) (int, error) {
	start := time.Now()
	n, err := m.Conn.Read(b)
	if n > 0 {
		m.rxTotal.Add(int64(n))
		if m.binder != nil {
			m.binder.OnBytes(int(m.link), int64(n), 0)
		}
		if m.sched != nil {
			m.sched.RecordBytes(m.link, int64(n), time.Since(start))
		}
		ReArmQuickAck(m.Conn)
	}
	return n, err
}

func (m *MeteredConn) Write(b []byte) (int, error) {
	start := time.Now()
	var (
		n   int
		err error
	)
	if m.firstWrite.CompareAndSwap(true, false) && m.fragmentTLS && isTLSClientHello(b) {
		n, err = writeFragmentedClientHello(m.Conn, b)
	} else {
		n, err = m.Conn.Write(b)
	}
	if n > 0 {
		m.txTotal.Add(int64(n))
		if m.binder != nil {
			m.binder.OnBytes(int(m.link), 0, int64(n))
		}
		if m.sched != nil {
			m.sched.RecordBytes(m.link, int64(n), time.Since(start))
		}
	}
	return n, err
}

func (m *MeteredConn) Close() error {
	var err error
	m.closeOnce.Do(func() {
		if m.sched != nil {
			m.sched.ReleaseFlow(m.link)
		}
		err = m.Conn.Close()
	})
	return err
}
