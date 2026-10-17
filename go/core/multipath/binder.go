// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android: per-link socket binding, synthetic-VIP
// dual-stack DNS resolution, and (later) the range splicer.
package multipath

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// LinkType identifies a physical egress link for socket binding and
// multipath scheduling decisions.
type LinkType int

const (
	LinkWiFi     LinkType = 1
	LinkCellular LinkType = 2
)

// SocketBinder pins a raw socket fd to one of the phone's physical networks
// and protects it from the VPN tunnel. Implemented on the Kotlin side via
// android.net.Network.bindSocket() + VpnService.protect(); the Go data plane
// only consumes this interface.
type SocketBinder interface {
	// BindAndProtect binds fd to the given link (see LinkType constants)
	// and protects it from the VPN. Returns false on failure, in which
	// case the dial is aborted.
	BindAndProtect(fd int64, networkType int) bool
	// OnBytes reports bytes transferred on a VIP flow, so the Scheduler
	// slots show real-time compounded throughput in the UI.
	// networkType: 1=WiFi, 2=Cellular. rxBytes=download, txBytes=upload.
	OnBytes(networkType int, rxBytes, txBytes int64)
}

// NewBoundDialer returns a net.Dialer whose sockets are bound to link and
// protected from the VPN via binder. Binding happens inside the Control
// callback — after the socket exists but before connect() completes — so no
// packet can leak through the TUN (no routing loop).
func NewBoundDialer(binder SocketBinder, link LinkType, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) {
				if binder == nil || !binder.BindAndProtect(int64(fd), int(link)) {
					bindErr = errors.New("multipath: bind and protect failed")
				}
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
}
