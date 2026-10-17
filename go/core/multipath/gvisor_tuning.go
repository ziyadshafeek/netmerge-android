// Package multipath implements the zero-VPS bandwidth-compounding data
// plane pieces for NetMerge Android.
package multipath

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// ConfigureGVisorTCP tunes a gVisor stack's TCP parameters for high-BDP
// dual-link bonding (Wi-Fi + 5G). Default gVisor buffers are sized for
// low-latency LANs and artificially cap throughput when bonding a 60ms-RTT
// 5G link.
//
// Call once after stack.New(), before serving traffic.
func ConfigureGVisorTCP(s *stack.Stack) {
	// SACK: recover from wireless loss without resending everything.
	sackOpt := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// Auto-tune receive buffer based on measured BDP.
	modOpt := tcpip.TCPModerateReceiveBufferOption(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &modOpt)

	// CUBIC handles high-BDP wireless links better than Reno.
	ccOpt := tcpip.CongestionControlOption("cubic")
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)

	// RACK loss detection: faster recovery on wireless links than classic RTO.
	rackOpt := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &rackOpt)

	// 4 MB auto-tuned send/receive windows so high-RTT cellular + Wi-Fi
	// BDP is never window-limited on the TUN side.
	recvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 256 * 1024,
		Max:     4 * 1024 * 1024,
	}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvOpt)
	sendOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: 256 * 1024,
		Max:     4 * 1024 * 1024,
	}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendOpt)

	ttlOpt := tcpip.DefaultTTLOption(64)
	_ = s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttlOpt)
	_ = s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttlOpt)
}
