// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated TCP types.

package tcp

import "sync"

// segmentEntry is the intrusive list element embedded in segment.
type segmentEntry struct {
	next *segment
	prev *segment
}

// Next returns the next segment, or nil.
func (e *segmentEntry) Next() *segment {
	return e.next
}

// segmentRefs is the intrusive reference count embedded in segment.
type segmentRefs struct {
	refCount int64
}

// InitRefs initializes the reference count to 1.
func (r *segmentRefs) InitRefs() {
	r.refCount = 1
}

// IncRef increments the reference count.
func (r *segmentRefs) IncRef() {
	r.refCount++
}

// DecRef decrements the reference count, calling destroy at zero.
func (r *segmentRefs) DecRef(destroy func()) {
	r.refCount--
	if r.refCount == 0 {
		destroy()
	}
}

// segmentList is an intrusive doubly-linked list of *segment.
type segmentList struct {
	head *segment
	tail *segment
}

// Front returns the first segment, or nil.
func (l *segmentList) Front() *segment {
	return l.head
}

// Back returns the last segment, or nil.
func (l *segmentList) Back() *segment {
	return l.tail
}

// Empty returns whether the list is empty.
func (l *segmentList) Empty() bool {
	return l.head == nil
}

// InsertAfter inserts s immediately after before, which must be in the list.
func (l *segmentList) InsertAfter(before, s *segment) {
	s.segmentEntry.prev = before
	s.segmentEntry.next = before.segmentEntry.next
	if before.segmentEntry.next != nil {
		before.segmentEntry.next.segmentEntry.prev = s
	} else {
		l.tail = s
	}
	before.segmentEntry.next = s
}

// PushBack appends s to the list.
func (l *segmentList) PushBack(s *segment) {
	s.segmentEntry.next = nil
	s.segmentEntry.prev = l.tail
	if l.tail != nil {
		l.tail.segmentEntry.next = s
	} else {
		l.head = s
	}
	l.tail = s
}

// Remove unlinks s from the list. s must be in the list.
func (l *segmentList) Remove(s *segment) {
	if s.segmentEntry.prev != nil {
		s.segmentEntry.prev.segmentEntry.next = s.segmentEntry.next
	} else {
		l.head = s.segmentEntry.next
	}
	if s.segmentEntry.next != nil {
		s.segmentEntry.next.segmentEntry.prev = s.segmentEntry.prev
	} else {
		l.tail = s.segmentEntry.prev
	}
	s.segmentEntry.next = nil
	s.segmentEntry.prev = nil
}

// endpointEntry is the intrusive list element embedded in Endpoint.
type endpointEntry struct {
	next *Endpoint
	prev *Endpoint
}

// Next returns the next endpoint, or nil.
func (e *endpointEntry) Next() *Endpoint {
	return e.next
}

// endpointList is an intrusive doubly-linked list of *Endpoint.
type endpointList struct {
	head *Endpoint
	tail *Endpoint
	size int
}

// Init resets the list to empty.
func (l *endpointList) Init() {
	l.head = nil
	l.tail = nil
	l.size = 0
}

// Front returns the first endpoint, or nil.
func (l *endpointList) Front() *Endpoint {
	return l.head
}

// Empty returns whether the list is empty.
func (l *endpointList) Empty() bool {
	return l.head == nil
}

// Len returns the number of endpoints.
func (l *endpointList) Len() int {
	return l.size
}

// PushBack appends ep to the list.
func (l *endpointList) PushBack(ep *Endpoint) {
	ep.endpointEntry.next = nil
	ep.endpointEntry.prev = l.tail
	if l.tail != nil {
		l.tail.endpointEntry.next = ep
	} else {
		l.head = ep
	}
	l.tail = ep
	l.size++
}

// Remove unlinks ep from the list and returns it. ep must be in the list.
func (l *endpointList) Remove(ep *Endpoint) any {
	if ep.endpointEntry.prev != nil {
		ep.endpointEntry.prev.endpointEntry.next = ep.endpointEntry.next
	} else {
		l.head = ep.endpointEntry.next
	}
	if ep.endpointEntry.next != nil {
		ep.endpointEntry.next.endpointEntry.prev = ep.endpointEntry.prev
	} else {
		l.tail = ep.endpointEntry.prev
	}
	ep.endpointEntry.next = nil
	ep.endpointEntry.prev = nil
	l.size--
	return ep
}

type segmentQueueMutex struct{ sync.Mutex }
type rcvQueueMutex struct{ sync.Mutex }
type protocolRWMutex struct{ sync.RWMutex }
type pendingProcessingMutex struct{ sync.Mutex }
type lastErrorMutex struct{ sync.Mutex }
type epQueueMutex struct{ sync.Mutex }
type dispatcherMutex struct{ sync.Mutex }
type sndQueueMutex struct{ sync.Mutex }
type rttMutex struct{ sync.Mutex }
type keepaliveMutex struct{ sync.Mutex }
type hasherMutex struct{ sync.Mutex }
type forwarderRequestMutex struct{ sync.Mutex }
type forwarderMutex struct{ sync.Mutex }
