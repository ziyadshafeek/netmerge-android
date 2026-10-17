package core

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// egressControl returns a Dialer Control func that pins the socket to the
// network's interface and protects it from the VPN. Both happen inside the
// Control callback, i.e. after the socket exists but BEFORE connect()
// completes, so the SYN can never leak through the TUN (no routing loop).
//
// SO_BINDTOIFINDEX (the ifindex, not the name) is used so no per-socket
// name lookup is needed; it has been unprivileged since Linux 5.7.
func (e *Engine) egressControl(sl *Slot) func(network, address string, c syscall.RawConn) error {
	if sl.IfIndex <= 0 {
		return nil
	}
	iface := sl.IfIndex
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, iface)
			if serr != nil {
				return
			}
			// Protect AFTER binding: the socket is fully configured and
			// still pre-connect, which is exactly what VpnService.protect
			// requires.
			if e.protector != nil {
				e.protector.Protect(int(fd))
			}
		}); err != nil {
			return err
		}
		return serr
	}
}

// testDialRewrite is a test-only hook (set by tun_integration_test.go):
// if non-nil and host is in the map, the egress dials the mapped host
// instead. This lets the integration test route the "internet" destination
// to a local echo server without complex policy routing.
var testDialRewrite map[string]string

// dialBound opens a TCP or UDP socket pinned to sl's interface for the
// given family. The source IP is also pinned (like net-merge) so the flow
// cannot wander to another link even if routes change mid-dial.
//
// Fallback: if the pinned dial fails at the link level (some carriers /
// 464XLAT setups, e.g. Jio, break SO_BINDTOIFINDEX or need CLAT), retry
// with VPN protection only and let the OS route normally. The link then
// still carries traffic; the scheduler prefers pinned links when pinning
// works.
func (e *Engine) dialBound(sl *Slot, f Family, proto, host string, port int, timeout time.Duration) (net.Conn, error) {
	c, err := e.dialWith(sl, f, proto, host, port, timeout, true)
	if err == nil || !isLinkDown(err) {
		return c, err
	}
	return e.dialWith(sl, f, proto, host, port, timeout, false)
}

// protectOnlyControl returns a Dialer Control func that protects the socket
// from the VPN without pinning it to any interface.
func (e *Engine) protectOnlyControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if e.protector == nil {
			return nil
		}
		var serr error
		if err := c.Control(func(fd uintptr) {
			e.protector.Protect(int(fd))
		}); err != nil {
			return err
		}
		return serr
	}
}

func (e *Engine) dialWith(sl *Slot, f Family, proto, host string, port int, timeout time.Duration, pin bool) (net.Conn, error) {
	ip := sl.ip(f)
	if pin && ip == nil {
		return nil, &linkError{err: errors.New("network has no address for this family"), down: true}
	}
	if testDialRewrite != nil {
		if mapped, ok := testDialRewrite[host]; ok {
			host = mapped
		}
	}
	network := proto + "4"
	if f == Fam6 {
		network = proto + "6"
	}
	var local net.Addr
	var control func(network, address string, c syscall.RawConn) error
	if pin {
		if proto == "tcp" {
			local = &net.TCPAddr{IP: ip}
		} else {
			local = &net.UDPAddr{IP: ip}
		}
		control = e.egressControl(sl)
	} else {
		control = e.protectOnlyControl()
	}
	d := net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		LocalAddr: local,
		Control:   control,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(port)))
}

func (e *Engine) dialBoundUDP(sl *Slot, f Family, host string, port int) (net.Conn, error) {
	return e.dialBound(sl, f, "udp", host, port, dialTimeout)
}

// linkError marks dial failures caused by the link itself (as opposed to
// the destination refusing). Those sideline the network for a cooldown.
type linkError struct {
	err  error
	down bool
}

func (l *linkError) Error() string { return l.err.Error() }
func (l *linkError) Unwrap() error { return l.err }

// isLinkDown classifies a dial error: link-level failures (no route, net
// down, timeout) mean the *network* is broken and deserve a retry on
// another network; refusals/DNS errors are about the destination.
func isLinkDown(err error) bool {
	var le *linkError
	if errors.As(err, &le) {
		return le.down
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false
	}
	is := func(e syscall.Errno) bool { return errors.Is(err, e) }
	switch {
	case is(syscall.EADDRNOTAVAIL), is(syscall.ENETDOWN), is(syscall.ENETUNREACH):
		return true
	case is(syscall.EHOSTUNREACH), is(syscall.ETIMEDOUT):
		return true
	case errors.Is(err, context.DeadlineExceeded):
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}
