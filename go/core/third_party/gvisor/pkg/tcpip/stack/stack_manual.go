// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated stack types
// (gVisor generates these from pkg/refs, pkg/ilist and pkg/sync templates
// at build time; the Go module does not ship them).

package stack

import "sync"
import "sync/atomic"

// addressStateRefs is the reference count for addressable endpoint state.
type addressStateRefs struct {
	refCount atomic.Int64
}

// InitRefs initializes the reference count to 1.
func (r *addressStateRefs) InitRefs() {
	r.refCount.Store(1)
}

// IncRef increments the reference count.
func (r *addressStateRefs) IncRef() {
	r.refCount.Add(1)
}

// TryIncRef increments the reference count unless it is zero.
func (r *addressStateRefs) TryIncRef() bool {
	for {
		c := r.refCount.Load()
		if c == 0 {
			return false
		}
		if r.refCount.CompareAndSwap(c, c+1) {
			return true
		}
	}
}

// ReadRefs returns the current reference count.
func (r *addressStateRefs) ReadRefs() int64 {
	return r.refCount.Load()
}

// DecRef decrements the reference count, calling destroy at zero.
func (r *addressStateRefs) DecRef(destroy func()) {
	if r.refCount.Add(-1) == 0 {
		destroy()
	}
}

// packetBufferRefs is the intrusive reference count embedded in PacketBuffer.
type packetBufferRefs struct {
	refCount int64
}

// InitRefs initializes the reference count to 1.
func (r *packetBufferRefs) InitRefs() {
	r.refCount = 1
}

// IncRef increments the reference count.
func (r *packetBufferRefs) IncRef() {
	r.refCount++
}

// DecRef decrements the reference count, calling destroy when it reaches zero.
func (r *packetBufferRefs) DecRef(destroy func()) {
	r.refCount--
	if r.refCount == 0 {
		destroy()
	}
}

// tupleEntry is the intrusive list element embedded in tuple.
type tupleEntry struct {
	next *tuple
	prev *tuple
}

// Next returns the next tuple in the list, or nil.
func (e *tupleEntry) Next() *tuple {
	return e.next
}

// tupleList is an intrusive doubly-linked list of *tuple.
type tupleList struct {
	head *tuple
	tail *tuple
}

// Front returns the first tuple, or nil if empty.
func (l *tupleList) Front() *tuple {
	return l.head
}

// PushFront prepends t to the list.
func (l *tupleList) PushFront(t *tuple) {
	t.tupleEntry.prev = nil
	t.tupleEntry.next = l.head
	if l.head != nil {
		l.head.tupleEntry.prev = t
	} else {
		l.tail = t
	}
	l.head = t
}

// Remove unlinks t from the list. t must be in the list.
func (l *tupleList) Remove(t *tuple) {
	if t.tupleEntry.prev != nil {
		t.tupleEntry.prev.tupleEntry.next = t.tupleEntry.next
	} else {
		l.head = t.tupleEntry.next
	}
	if t.tupleEntry.next != nil {
		t.tupleEntry.next.tupleEntry.prev = t.tupleEntry.prev
	} else {
		l.tail = t.tupleEntry.prev
	}
	t.tupleEntry.next = nil
	t.tupleEntry.prev = nil
}

// The following are the mutex wrapper types gVisor generates from
// pkg/sync templates. Plain embeddings of sync.RWMutex / sync.Mutex.
type connRWMutex struct{ sync.RWMutex }
type stateConnRWMutex struct{ sync.RWMutex }
type connTrackRWMutex struct{ sync.RWMutex }

// bucketLockClass is the lock-ordering token type for nested bucket locks.
type bucketLockClass struct{}

// bucketLockOthertuple is the lock class used when locking a second
// conntrack bucket while already holding one.
var bucketLockOthertuple bucketLockClass

type bucketRWMutex struct{ sync.RWMutex }

// NestedLock locks the mutex, declaring the given lock ordering class.
// (Lock ordering is not enforced in this build; the class is documentation.)
func (m *bucketRWMutex) NestedLock(_ bucketLockClass) { m.Lock() }

// NestedUnlock unlocks the mutex.
func (m *bucketRWMutex) NestedUnlock(_ bucketLockClass) { m.Unlock() }
type transportEndpointsRWMutex struct{ sync.RWMutex }
type endpointsByNICRWMutex struct{ sync.RWMutex }
type multiPortEndpointRWMutex struct{ sync.RWMutex }
type stackRWMutex struct{ sync.RWMutex }
type routeStackRWMutex struct{ sync.RWMutex }
type nicRWMutex struct{ sync.RWMutex }
type neighborEntryRWMutex struct{ sync.RWMutex }
type neighborCacheRWMutex struct{ sync.RWMutex }
type ipTablesRWMutex struct{ sync.RWMutex }
type cleanupEndpointsMutex struct{ sync.Mutex }
type routeRWMutex struct{ sync.RWMutex }
type packetsPendingLinkResolutionMutex struct{ sync.Mutex }
type packetEndpointListRWMutex struct{ sync.RWMutex }
type packetEPsRWMutex struct{ sync.RWMutex }
type bridgeRWMutex struct{ sync.RWMutex }
type addressableEndpointStateRWMutex struct{ sync.RWMutex }
type addressStateRWMutex struct{ sync.RWMutex }

// neighborEntryEntry is the intrusive list element embedded in neighborEntry.
type neighborEntryEntry struct {
	next *neighborEntry
	prev *neighborEntry
}

// Next returns the next entry in the list, or nil.
func (e *neighborEntryEntry) Next() *neighborEntry {
	return e.next
}

// neighborEntryList is an intrusive doubly-linked list of *neighborEntry,
// used as the neighbor cache LRU.
type neighborEntryList struct {
	head *neighborEntry
	tail *neighborEntry
}

// Front returns the first entry, or nil if empty.
func (l *neighborEntryList) Front() *neighborEntry {
	return l.head
}

// Back returns the last entry, or nil if empty.
func (l *neighborEntryList) Back() *neighborEntry {
	return l.tail
}

// PushFront prepends e to the list.
func (l *neighborEntryList) PushFront(e *neighborEntry) {
	e.neighborEntryEntry.prev = nil
	e.neighborEntryEntry.next = l.head
	if l.head != nil {
		l.head.neighborEntryEntry.prev = e
	} else {
		l.tail = e
	}
	l.head = e
}

// Remove unlinks e from the list. e must be in the list.
func (l *neighborEntryList) Remove(e *neighborEntry) {
	if e.neighborEntryEntry.prev != nil {
		e.neighborEntryEntry.prev.neighborEntryEntry.next = e.neighborEntryEntry.next
	} else {
		l.head = e.neighborEntryEntry.next
	}
	if e.neighborEntryEntry.next != nil {
		e.neighborEntryEntry.next.neighborEntryEntry.prev = e.neighborEntryEntry.prev
	} else {
		l.tail = e.neighborEntryEntry.prev
	}
	e.neighborEntryEntry.next = nil
	e.neighborEntryEntry.prev = nil
}
