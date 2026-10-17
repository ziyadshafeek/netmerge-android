module netmerge/core

go 1.26.0

require (
	golang.org/x/sys v0.49.0
	gvisor.dev/gvisor v0.0.0-20260107231741-826b78e0691b
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
)

tool golang.org/x/mobile/cmd/gobind

replace gvisor.dev/gvisor => ./third_party/gvisor
