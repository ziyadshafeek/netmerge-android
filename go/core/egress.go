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

// egressControl returns a Dialer Control func that binds the socket to the
// network via Android's Network.bindSocket() (through the Kotlin Protector)
// and protects it from the VPN. Both happen inside the Control callback,
// i.e. after the socket exists but BEFORE connect() completes, so the SYN
// can never leak through the TUN (no routing loop).
//
// We use Network.bindSocket() instead of raw SO_BINDTOIFINDEX because the
// latter bypasses Android's 464XLAT/CLAT translator on carriers like Jio,
// breaking IPv4. Network.bindSocket() sets the correct fwmark and handles
// both native IPv6 and translated IPv4.
func (e *Engine) egressControl(sl *Slot) func(network, address string, c syscall.RawConn) error {
	netType := NetWiFi
	if sl.Transport == "CELLULAR" {
		netType = NetCellular
	}
	return func(network, address string, c syscall.RawConn) error {
		var berr error
		if err := c.Control(func(fd uintptr) {
			// Prefer Android's Network.bindSocket via Kotlin; fall back to
			// raw SO_BINDTOIFINDEX if the binder is unavailable.
			if e.protector != nil && e.protector.BindAndProtect(int(fd), netType) {
				return
			}
			if sl.IfIndex > 0 {
				berr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, sl.IfIndex)
				if berr != nil {
					return
				}
			}
			if e.protector != nil {
				e.protector.Protect(int(fd))
			}
		}); err != nil {
			return err
		}
		return berr
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
	// NAT64 fallback: if this is cellular (e.g. Jio IPv6-only) and the target
	// is an IPv4 literal that failed with ENETUNREACH, try RFC 6052 synthesis
	// (64:ff9b::/96) over native IPv6. This handles the case where Android
	// doesn't run clatd on the secondary cellular interface.
	if sl.Transport == "CELLULAR" && f == Fam4 {
		if nat64Host := synthesizeNAT64(host); nat64Host != "" {
			if c6, err6 := e.dialWith(sl, Fam6, proto, nat64Host, port, timeout, true); err6 == nil {
				return c6, nil
			}
		}
	}
	return e.dialWith(sl, f, proto, host, port, timeout, false)
}

// synthesizeNAT64 converts an IPv4 address (e.g. "1.1.1.1") into an RFC 6052
// Well-Known Prefix IPv6 address ("64:ff9b::101:101") so IPv6-only cellular
// (Jio) can reach IPv4 servers even when Android doesn't run clatd on the
// secondary cellular interface.
func synthesizeNAT64(ipv4Str string) string {
	ip := net.ParseIP(ipv4Str).To4()
	if ip == nil {
		return ""
	}
	// 64:ff9b::/96 + 32 bits of IPv4
	nat64IP := net.IP{
		0x00, 0x64, 0xff, 0x9b,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		ip[0], ip[1], ip[2], ip[3],
	}
	return nat64IP.String()
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
