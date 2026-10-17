// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated fdbased mutex types.

package fdbased

import "sync"

type processorMutex struct{ sync.Mutex }
type injectableEndpointRWMutex struct{ sync.RWMutex }
type endpointRWMutex struct{ sync.RWMutex }
