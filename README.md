# NetMerge for Android

Use all your phone's networks at once — per-connection load balancing over
Wi-Fi and mobile data, inspired by
[rohit267/net-merge](https://github.com/rohit267/net-merge).

## How it works

- A `VpnService` creates a TUN interface and captures the phone's traffic.
- A Go data plane (gVisor netstack, built with gomobile) terminates TCP/UDP
  inside the tunnel and opens the real connection out through **one** of the
  currently available networks (Wi-Fi, cellular, …).
- Each new connection is assigned to a network by the scheduler
  (round-robin across healthy networks), exactly like net-merge's
  per-connection load balancing on desktop.
- Egress sockets are bound to the chosen network's source IP and protected
  from the VPN so there is no routing loop.

This is **per-connection** load balancing: one download using many
connections gets the combined speed; a single connection is limited to one
link's speed. Same semantics as the original net-merge.

## Project layout

- `app/` — Kotlin Android app (`com.netmerge.android`): VPNService, network
  tracking via ConnectivityManager, Compose UI, stats.
- `go/core` — Go data plane: TUN ↔ netstack bridge, TCP/UDP forwarders,
  scheduler, egress dialer with interface binding. Built as an AAR with
  gomobile (`app/libs/netmerge.aar`).

## Build

CI builds a debug APK on every push to `main` (see Actions). The APK
includes `app/libs/netmerge.aar`, which is committed to the repo.

To rebuild the AAR after changing `go/core` (needs Go ≥ 1.26, Android NDK,
JDK 17):

```sh
cd go/core
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -o ../../app/libs/netmerge.aar -target android -androidapi 26 .
```

Note: `gvisor.dev/gvisor`'s Go module does not ship its Bazel-generated
files (intrusive list / refcount / mutex wrappers). The missing pieces are
hand-written under `go/core/third_party/gvisor/.../*_manual.go`, and gVisor
is consumed via a `replace` directive (a `vendor/` directory breaks
`gomobile bind`'s module-graph computation).

## License

MIT — like the upstream [rohit267/net-merge](https://github.com/rohit267/net-merge)
this is inspired by. See upstream for the original copyright notice.

## Status

Work in progress — built and battle-tested from scratch for Android.
