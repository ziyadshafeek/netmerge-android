package core

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// End-to-end through the packet path.
//
// A real TUN is created via /dev/net/tun (proving TUNSETIFF works as root),
// then a SOCK_DGRAM socketpair carries packets: the test crafts raw IP/TCP
// packets (like an app's traffic) into one end, the core's netstack
// (fdbased) reads them from the other, terminates TCP, and the
// scheduler/egress dial out via the fake "lo" network to a local echo server
// standing in for the internet. Bytes must flow both ways.
//
// A socketpair is used instead of routing via the TUN because the sandbox
// firewall blocks the kernel-routed path; fdbased only needs a packet-
// oriented fd, so the data-plane logic under test is identical.
//
// Skipped unless NETMERGE_TEST_TUN=1 (needs /dev/net/tun; we run it as root
// on the build machine).
func TestTunIntegration(t *testing.T) {
	if os.Getenv("NETMERGE_TEST_TUN") != "1" {
		t.Skip("set NETMERGE_TEST_TUN=1 to run the TUN integration test")
	}

	// 1. Prove a real TUN can be created.
	tunFd, tunName, err := createTun("netmerge%d")
	if err != nil {
		t.Fatalf("create tun: %v", err)
	}
	if err := setTunAddr(tunName, "10.0.0.1", 24); err != nil {
		t.Fatalf("assign tun addr: %v", err)
	}
	if err := setIffUp(tunName); err != nil {
		t.Fatalf("bring tun up: %v", err)
	}
	t.Logf("real TUN %s up", tunName)
	unix.Close(tunFd) // creation proven; packet I/O uses the socketpair below

	// 2. Socketpair for deterministic packet I/O with the core.
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sp[0])
	defer unix.Close(sp[1])

	// Local echo server standing in for "the internet".
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	echoPort := ln.Addr().(*net.TCPAddr).Port

	if s := Start(sp[0], noopProtector{}, "{}"); s != "" {
		t.Fatalf("Start: %s", s)
	}
	defer func() {
		Stop()
		testDialRewrite = nil
	}()

	loIdx, err := loIfIndex()
	if err != nil {
		t.Fatal(err)
	}
	UpdateNetworks(fmt.Sprintf(
		`[{"id":"lo","name":"lo","displayName":"Loopback","transport":"OTHER",`+
			`"ifindex":%d,"ipv4":"127.0.0.1","ipv6":"","dns":["127.0.0.1"]}]`, loIdx))

	// Rewrite the "internet" destination to the local echo server.
	testDialRewrite = map[string]string{"10.0.0.2": "127.0.0.1"}

	// Give the stack a beat to come up.
	time.Sleep(300 * time.Millisecond)

	tc := &tunClient{fd: sp[1]}
	clientIP := net.ParseIP("10.0.0.2").To4()
	serverIP := net.ParseIP("10.0.0.2").To4() // non-loopback; rewritten to 127.0.0.1 on egress
	clientPort := uint16(40000)

	// 1. SYN
	clientSeq := uint32(1000)
	tc.writePacket(t, buildTCPPacket(clientIP, serverIP, clientPort,
		uint16(echoPort), clientSeq, 0, tcpSYN, nil))

	// 2. SYN-ACK
	var serverSeq uint32
	deadline := time.Now().Add(10 * time.Second)
	for {
		pkt := tc.readPacket(t, deadline)
		if pkt == nil {
			t.Fatal("timed out waiting for SYN-ACK")
		}
		th := parseTCP(pkt)
		if th == nil || th.flags&tcpSYN == 0 || th.flags&tcpACK == 0 {
			continue
		}
		if th.ack != clientSeq+1 {
			continue
		}
		serverSeq = th.seq
		break
	}
	t.Logf("handshake: server seq=%d", serverSeq)

	// 3. ACK
	tc.writePacket(t, buildTCPPacket(clientIP, serverIP, clientPort,
		uint16(echoPort), clientSeq+1, serverSeq+1, tcpACK, nil))

	// 4. Data
	payload := []byte("hello-netmerge")
	tc.writePacket(t, buildTCPPacket(clientIP, serverIP, clientPort,
		uint16(echoPort), clientSeq+1, serverSeq+1, tcpPSH|tcpACK, payload))

	// 5. Echo must come back through the TUN.
	deadline = time.Now().Add(10 * time.Second)
	var echoed bool
	for {
		pkt := tc.readPacket(t, deadline)
		if pkt == nil {
			t.Fatal("timed out waiting for echo")
		}
		th := parseTCP(pkt)
		if th == nil || len(th.payload) == 0 {
			continue
		}
		if string(th.payload) == string(payload) {
			echoed = true
			// ACK the echo.
			tc.writePacket(t, buildTCPPacket(clientIP, serverIP, clientPort,
				uint16(echoPort), clientSeq+1+uint32(len(payload)),
				th.seq+uint32(len(th.payload)), tcpACK, nil))
			break
		}
	}
	if !echoed {
		t.Fatal("echo payload never arrived")
	}

	// 6. Stats must show bytes both ways.
	stats := GetStats()
	var st struct {
		Running bool `json:"running"`
		Totals  struct {
			TxBytes int64 `json:"txBytes"`
			RxBytes int64 `json:"rxBytes"`
		} `json:"totals"`
	}
	if err := json.Unmarshal([]byte(stats), &st); err != nil {
		t.Fatalf("stats: %v", err)
	}
	if !st.Running || st.Totals.TxBytes == 0 || st.Totals.RxBytes == 0 {
		t.Fatalf("bad stats: %s", stats)
	}
	t.Logf("stats: tx=%d rx=%d", st.Totals.TxBytes, st.Totals.RxBytes)
}

type noopProtector struct{}

func (noopProtector) Protect(fd int) {}
func (noopProtector) BindAndProtect(fd int, networkType int) bool { return false }

func loIfIndex() (int, error) {
	ifc, err := net.InterfaceByName("lo")
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}

const (
	iffTun  = 0x0001
	iffNoPI  = 0x1000
	tunSetIFF = 0x400454ca
)

// createTun opens /dev/net/tun and creates a TUN device (no packet-info
// header). Returns the fd and the kernel-assigned interface name.
func createTun(name string) (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return 0, "", err
	}
	var ifr [40]byte
	copy(ifr[:], name)
	binary.LittleEndian.PutUint16(ifr[16:18], iffTun|iffNoPI)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return 0, "", errno
	}
	ifname := string(ifr[:bytes.IndexByte(ifr[:], 0)])
	return fd, ifname, nil
}

// setIffUp marks the interface UP (TUN writes fail with EIO while down).
func setIffUp(ifname string) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	var ifr [40]byte
	copy(ifr[:], ifname)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock),
		uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}
	flags := binary.LittleEndian.Uint16(ifr[16:18])
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	binary.LittleEndian.PutUint16(ifr[16:18], flags)
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(sock),
		uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// Linux ioctl numbers not in x/sys/unix.
const (
	sioCSIFAddr    = 0x8916
	sioCSIFNetmask = 0x891c
)

// setTunAddr assigns an IPv4 address/prefix to the interface so the kernel
// routes that subnet via the TUN (letting test traffic reach fdbased).
func setTunAddr(ifname, ipStr string, prefixLen int) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	setAddr := func(ioctl uintptr, ip net.IP) error {
		var ifr [40]byte
		copy(ifr[:], ifname)
		// struct sockaddr at ifr[16:]: family(2) + port(2) + addr(4)
		binary.LittleEndian.PutUint16(ifr[16:18], unix.AF_INET)
		copy(ifr[20:24], ip.To4())
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock),
			ioctl, uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 {
			return errno
		}
		return nil
	}
	if err := setAddr(sioCSIFAddr, net.ParseIP(ipStr)); err != nil {
		return err
	}
	return setAddr(sioCSIFNetmask, net.IP(net.CIDRMask(prefixLen, 32)))
}

// tunClient crafts raw IP/TCP packets on the TUN fd.
type tunClient struct {
	fd int
}

func (c *tunClient) writePacket(t *testing.T, pkt []byte) {
	t.Helper()
	for len(pkt) > 0 {
		n, err := unix.Write(c.fd, pkt)
		if err == unix.EAGAIN {
			c.wait(t, unix.POLLOUT, 5*time.Second)
			continue
		}
		if err != nil {
			t.Fatalf("tun write: %v", err)
		}
		pkt = pkt[n:]
	}
}

func (c *tunClient) readPacket(t *testing.T, deadline time.Time) []byte {
	t.Helper()
	for {
		now := time.Now()
		if now.After(deadline) {
			return nil
		}
		c.wait(t, unix.POLLIN, time.Until(deadline))
		buf := make([]byte, 9000)
		n, err := unix.Read(c.fd, buf)
		if err == unix.EAGAIN {
			continue
		}
		if err != nil {
			t.Fatalf("tun read: %v", err)
		}
		if n > 0 {
			return buf[:n]
		}
	}
}

func (c *tunClient) wait(t *testing.T, events uint16, timeout time.Duration) {
	t.Helper()
	ms := int(timeout.Milliseconds())
	if ms < 0 {
		ms = 0
	}
	fds := []unix.PollFd{{Fd: int32(c.fd), Events: int16(events)}}
	n, err := unix.Poll(fds, ms)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n == 0 {
		t.Fatalf("poll timed out")
	}
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	// Pseudo-header.
	ph := make([]byte, 12)
	copy(ph[0:4], src.To4())
	copy(ph[4:8], dst.To4())
	ph[8] = 0
	ph[9] = 6 // TCP
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcp)))
	var sum uint32
	for _, b := range [][]byte{ph, tcp} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// buildTCPPacket crafts an IPv4/TCP packet with correct checksums.
func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	seq, ack uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP, dstIP, tcp))

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234) // id
	ip[8] = 64                                 // ttl
	ip[9] = 6                                  // TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))
	return append(ip, tcp...)
}

type tcpParsed struct {
	flags   byte
	seq     uint32
	ack     uint32
	payload []byte
}

func parseTCP(pkt []byte) *tcpParsed {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 {
		return nil
	}
	tcp := pkt[ihl:]
	hlen := int(tcp[12]>>4) * 4
	if len(tcp) < hlen {
		return nil
	}
	return &tcpParsed{
		flags:   tcp[13],
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		ack:     binary.BigEndian.Uint32(tcp[8:12]),
		payload: tcp[hlen:],
	}
}
