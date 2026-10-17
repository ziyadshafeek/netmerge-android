// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated bits helpers
// (gVisor generates arch-specific mask helpers at build time; the Go
// module does not ship them).

package bits

// MaskOf64 returns a uint64 with only bit i set.
func MaskOf64(i int) uint64 {
	return uint64(1) << uint(i)
}
