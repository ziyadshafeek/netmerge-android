package core

import (
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type recordProtector struct {
	fds []int
}

func (p *recordProtector) Protect(fd int) { p.fds = append(p.fds, fd) }

// The Control callback must pin the socket to the interface AND protect it,
// before connect() runs.
func TestEgressControlBindsAndProtects(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo interface")
	}
	prot := &recordProtector{}
	e := &Engine{protector: prot}
	sl := &Slot{IfIndex: iface.Index}
	ctl := e.egressControl(sl)
	if ctl == nil {
		t.Fatal("nil control for valid ifindex")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	f := os.NewFile(uintptr(fd), "sock")
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl("tcp4", "1.2.3.4:80", rc); err != nil {
		t.Fatalf("control: %v", err)
	}

	idx, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	if err != nil {
		t.Fatalf("getsockopt: %v", err)
	}
	if idx != iface.Index {
		t.Fatalf("SO_BINDTOIFINDEX = %d, want %d", idx, iface.Index)
	}
	if len(prot.fds) != 1 || prot.fds[0] != fd {
		t.Fatalf("protector got %v, want [%d]", prot.fds, fd)
	}
}

// No ifindex -> no control func (unbound dial, e.g. before networks arrive).
func TestEgressControlNilWithoutIfIndex(t *testing.T) {
	e := &Engine{}
	if ctl := e.egressControl(&Slot{}); ctl != nil {
		t.Fatal("want nil control for ifindex 0")
	}
}

func TestIsLinkDown(t *testing.T) {
	if !isLinkDown(syscall.ENETUNREACH) {
		t.Fatal("ENETUNREACH should be link-down")
	}
	if !isLinkDown(syscall.ETIMEDOUT) {
		t.Fatal("ETIMEDOUT should be link-down")
	}
	if isLinkDown(syscall.ECONNREFUSED) {
		t.Fatal("ECONNREFUSED is about the destination, not the link")
	}
	if isLinkDown(&net.DNSError{IsNotFound: true}) {
		t.Fatal("DNS error should not sideline the network")
	}
}
