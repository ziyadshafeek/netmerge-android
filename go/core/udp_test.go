package core

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// The sandbox blocks sendto() from unconnected UDP sockets, so these tests
// use in-memory fakes instead of real sockets. The relay only needs the
// net.PacketConn / net.Conn interfaces, which the fakes implement
// faithfully, including timeout errors for the idle logic.

type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

// fakePacketConn is an in-memory net.PacketConn. Inbound datagrams are fed
// by the test; outbound datagrams are captured for assertions. Reads block
// briefly then report a timeout, like a socket with a read deadline.
type fakePacketConn struct {
	mu       sync.Mutex
	inbound  chan []byte
	outbound chan []byte
	raddr    net.Addr
	closed   bool
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		raddr:    fakeAddr("127.0.0.1:9999"),
	}
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-f.inbound:
		return copy(b, p), f.raddr, nil
	case <-time.After(20 * time.Millisecond):
		return 0, nil, fakeTimeoutError{}
	}
}

func (f *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("closed")
	}
	cp := append([]byte(nil), b...)
	select {
	case f.outbound <- cp:
	default:
	}
	return len(b), nil
}

func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr                { return fakeAddr("local") }
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// fakeStreamConn adapts fakePacketConn to the stream-oriented net.Conn the
// relay uses for the upstream side.
type fakeStreamConn struct {
	*fakePacketConn
}

func (f *fakeStreamConn) Read(b []byte) (int, error) {
	n, _, err := f.fakePacketConn.ReadFrom(b)
	return n, err
}

func (f *fakeStreamConn) Write(b []byte) (int, error) {
	return f.fakePacketConn.WriteTo(b, nil)
}

func (f *fakeStreamConn) RemoteAddr() net.Addr { return fakeAddr("remote") }

func udpTestEngine() *Engine {
	return &Engine{
		scheduler:   newScheduler(nil),
		udpSessions: map[string]*udpSession{},
		stopCh:      make(chan struct{}),
	}
}

func (e *Engine) testSession(key string, tunConn net.PacketConn, upstream net.Conn) *udpSession {
	us := &udpSession{
		key: key, tunConn: tunConn, upstream: upstream,
		slot: &Slot{}, family: Fam4, closeCh: make(chan struct{}),
	}
	us.touch()
	e.udpMu.Lock()
	e.udpSessions[key] = us
	e.udpMu.Unlock()
	return us
}

func (e *Engine) sessionAlive(key string) bool {
	e.udpMu.Lock()
	defer e.udpMu.Unlock()
	_, ok := e.udpSessions[key]
	return ok
}

func recvWithTimeout(t *testing.T, ch chan []byte, what string) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func TestUDPSessionIdleTimeout(t *testing.T) {
	oldIdle, oldPoll := udpIdleTimeout, udpPollInterval
	udpIdleTimeout = 200 * time.Millisecond
	udpPollInterval = 50 * time.Millisecond
	defer func() { udpIdleTimeout, udpPollInterval = oldIdle, oldPoll }()

	e := udpTestEngine()
	tunFake := newFakePacketConn()
	upFake := &fakeStreamConn{newFakePacketConn()}
	us := e.testSession("test/1", tunFake, upFake)
	go e.relayUDP(us, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999})

	// App -> internet.
	tunFake.inbound <- []byte("hello")
	if got := recvWithTimeout(t, upFake.outbound, "upstream datagram"); string(got) != "hello" {
		t.Fatalf("app->net got %q", got)
	}

	// Internet -> app.
	upFake.inbound <- []byte("world")
	if got := recvWithTimeout(t, tunFake.outbound, "tun datagram"); string(got) != "world" {
		t.Fatalf("net->app got %q", got)
	}

	// Session is alive while traffic flows.
	if !e.sessionAlive(us.key) {
		t.Fatal("session vanished while active")
	}

	// Now stay quiet: the session must idle out.
	deadline := time.Now().Add(5 * time.Second)
	for e.sessionAlive(us.key) {
		if time.Now().After(deadline) {
			t.Fatal("session did not idle out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !us.closed.Load() {
		t.Fatal("session not marked closed after idle timeout")
	}
}

// A one-directional quiet spell shorter than the timeout must NOT kill the
// session: only true idleness (no traffic either way) expires it.
func TestUDPSessionSurvivesOneSidedQuiet(t *testing.T) {
	oldIdle, oldPoll := udpIdleTimeout, udpPollInterval
	udpIdleTimeout = 600 * time.Millisecond
	udpPollInterval = 50 * time.Millisecond
	defer func() { udpIdleTimeout, udpPollInterval = oldIdle, oldPoll }()

	e := udpTestEngine()
	tunFake := newFakePacketConn()
	upFake := &fakeStreamConn{newFakePacketConn()}
	us := e.testSession("test/2", tunFake, upFake)
	go e.relayUDP(us, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999})

	// Keep the app->net direction busy; the net->app side stays quiet.
	for i := 0; i < 8; i++ {
		tunFake.inbound <- []byte("ping")
		if got := recvWithTimeout(t, upFake.outbound, "upstream datagram"); string(got) != "ping" {
			t.Fatalf("app->net got %q", got)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !e.sessionAlive(us.key) {
		t.Fatal("session expired despite app->net traffic")
	}
}

func TestDNSSeverSelection(t *testing.T) {
	e := &Engine{}
	sl := &Slot{DNS: []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("2001:4860:4860::8888"),
	}}
	if got := e.dnsServerFor(sl, Fam4); got.String() != "8.8.8.8" {
		t.Fatalf("v4 dns = %v", got)
	}
	if got := e.dnsServerFor(sl, Fam6); got.String() != "2001:4860:4860::8888" {
		t.Fatalf("v6 dns = %v", got)
	}
	// Family mismatch falls back to whatever the network has.
	sl2 := &Slot{DNS: []net.IP{net.ParseIP("8.8.8.8")}}
	if got := e.dnsServerFor(sl2, Fam6); got.String() != "8.8.8.8" {
		t.Fatalf("fallback dns = %v", got)
	}
	if got := e.dnsServerFor(&Slot{}, Fam4); got != nil {
		t.Fatalf("no dns = %v, want nil", got)
	}
}
