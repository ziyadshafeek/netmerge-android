package multipath

import (
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
	tcpQuickAck = 0xc  // TCP_QUICKACK
	tcpMaxSeg   = 0x2  // TCP_MAXSEG
	ipTosDSCP   = 0x28 // Assured Forwarding AF11 / Low-Latency Throughput
	cellSafeMSS = 1360 // Prevents 5G NR GTP-U + NAT64/464XLAT PMTU blackholes
	wifiSafeMSS = 1440 // Safe MSS for PPPoE/Fiber Wi-Fi uplinks

	spliceBufSize = 256 * 1024
)

// SocketBinder binds raw socket descriptors to physical Android Networks (Wi-Fi / Cellular)
// and reports real-time per-link byte telemetry.
type SocketBinder interface {
	BindAndProtect(fd int64, networkType int) bool
	OnBytes(networkType int, rxBytes int64, txBytes int64)
}

var spliceBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, spliceBufSize)
		return &buf
	},
}

// NewBoundDialer creates a net.Dialer strictly pinned to the target physical interface
// with pre-connect kernel socket tuning.
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
				// Tune kernel socket buffers before SYN so TCP window scale factor is maximized.
				_ = syscall.SetsockoptInt(rawFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, socketBufSize)
				_ = syscall.SetsockoptInt(rawFD, syscall.SOL_SOCKET, syscall.SO_SNDBUF, socketBufSize)
				_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_IP, syscall.IP_TOS, ipTosDSCP)

				if network == "tcp" || network == "tcp4" || network == "tcp6" {
					_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
					_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_TCP, tcpQuickAck, 1)
					if link == LinkCellular {
						_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_TCP, tcpMaxSeg, cellSafeMSS)
					} else {
						_ = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_TCP, tcpMaxSeg, wifiSafeMSS)
					}
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

// MeteredConn wraps a net.Conn to report exact RX/TX byte counts to SocketBinder
// and Scheduler without locks on the hot path.
type MeteredConn struct {
	net.Conn
	binder    SocketBinder
	sched     *Scheduler
	link      LinkType
	rxTotal   atomic.Int64
	txTotal   atomic.Int64
	closeOnce sync.Once
}

func NewMeteredConn(c net.Conn, binder SocketBinder, sched *Scheduler, link LinkType) *MeteredConn {
	return &MeteredConn{
		Conn:   c,
		binder: binder,
		sched:  sched,
		link:   link,
	}
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
	n, err := m.Conn.Write(b)
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
