// Package core is the Go data plane for NetMerge on Android.
//
// It is built with gomobile into an AAR, so the exported surface is kept
// tiny and gomobile-compatible: only the Protector interface, ints, strings
// and JSON cross the boundary. Everything else lives behind Start/Stop.
//
// Architecture (ported from rohit267/net-merge, adapted for Android):
//
//	A Kotlin VpnService captures traffic on a TUN fd and hands the raw fd to
//	Start. A gVisor netstack (stack.go) terminates TCP/UDP inside the tunnel.
//	Every new flow is assigned to one physical network by the scheduler
//	(scheduler.go, weighted least-active-flows per address family, exactly
//	like net-merge). Egress sockets are bound to the chosen network's
//	interface (SO_BINDTOIFINDEX) and protected from the VPN via the
//	Protector callback before connect() runs (egress.go), so there is no
//	routing loop. Health probing (probe.go) keeps dead links out of the
//	rotation, and GetStats (stats.go) reports per-network counters as JSON.
package core

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Protector is implemented in Kotlin. It must call VpnService.protect(fd)
// so the egress socket bypasses the TUN interface. It is invoked from the
// dialer's Control callback, i.e. after the socket exists but before
// connect() completes.
//
// BindAndProtect is the preferred path on Android: it calls
// VpnService.protect(fd) AND Network.bindSocket() for the given network
// type (1=Wi-Fi, 2=Cellular). Network.bindSocket sets the correct kernel
// fwmark, which handles 464XLAT/CLAT on carriers like Jio - raw
// SO_BINDTOIFINDEX bypasses the translator and breaks IPv4.
type Protector interface {
	Protect(fd int)
	BindAndProtect(fd int, networkType int) bool
}

// Network types for BindAndProtect (must match Kotlin).
const (
	NetWiFi     = 1
	NetCellular = 2
)

var (
	apiMu sync.Mutex
	eng   *Engine
)

// Start brings the data plane up on an already-open TUN file descriptor.
//
//	tunFd      - fd of the TUN device created by the VpnService (we never
//	             close it; Kotlin owns it).
//	protector  - Kotlin callback used to protect egress sockets.
//	configJSON - optional JSON object, e.g. {"weights":{"wlan0":2.0}}.
//	             Manual weights disable auto weight measurement.
//
// Returns "" on success, otherwise a human-readable error. Calling Start
// twice without Stop in between returns an error instead of crashing.
// It never panics: internal panics are recovered and reported as errors.
func Start(tunFd int, protector Protector, configJSON string) (errStr string) {
	defer func() {
		if r := recover(); r != nil {
			errStr = fmt.Sprintf("start panicked: %v", r)
		}
	}()
	apiMu.Lock()
	defer apiMu.Unlock()

	if eng != nil {
		return "already started: call Stop() first"
	}
	if tunFd < 0 {
		return "invalid tun fd"
	}
	if protector == nil {
		return "protector is nil"
	}
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return fmt.Sprintf("bad config: %v", err)
	}
	e, err := newEngine(tunFd, protector, cfg)
	if err != nil {
		return err.Error()
	}
	eng = e
	return ""
}

// UpdateNetworks replaces the set of usable networks. Safe to call any
// time, including before Start (it is a no-op then). networksJSON is a JSON
// array like:
//
//	[{"id":"101","name":"wlan0","displayName":"Wi-Fi","transport":"WIFI",
//	  "ifindex":12,"ipv4":"192.168.1.10","ipv6":"","dns":["192.168.1.1"]}]
//
// Networks absent from the list are retired once their flows drain.
func UpdateNetworks(networksJSON string) {
	defer func() { _ = recover() }()
	apiMu.Lock()
	e := eng
	apiMu.Unlock()
	if e == nil {
		return
	}
	var nets []NetworkInfo
	if err := json.Unmarshal([]byte(networksJSON), &nets); err != nil {
		return
	}
	e.scheduler.Update(nets)
}

// Stop tears the data plane down. Safe to call when not started.
func Stop() {
	defer func() { _ = recover() }()
	apiMu.Lock()
	e := eng
	eng = nil
	apiMu.Unlock()
	if e != nil {
		e.close()
	}
}

// GetStats returns a JSON snapshot, e.g.
//
//	{"running":true,"networks":[
//	  {"id":"101","displayName":"Wi-Fi","transport":"WIFI","state":"up",
//	   "txBytes":123,"rxBytes":456,"activeFlows":3,"weight":1.0}],
//	 "totals":{"txBytes":1,"rxBytes":2,"activeFlows":3}}
//
// When stopped it returns {"running":false,...}. It never panics.
func GetStats() (out string) {
	defer func() {
		if recover() != nil {
			out = `{"running":false}`
		}
	}()
	apiMu.Lock()
	e := eng
	apiMu.Unlock()
	if e == nil {
		return `{"running":false,"networks":[],"totals":{"txBytes":0,"rxBytes":0,"activeFlows":0}}`
	}
	return e.statsJSON()
}
