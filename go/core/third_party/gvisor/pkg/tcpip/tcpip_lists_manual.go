// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated socket error queue
// types (gVisor generates these from pkg/ilist templates at build time;
// the Go module does not ship them).

package tcpip

// sockErrorEntry is the intrusive list element embedded in SockError.
type sockErrorEntry struct {
	next *SockError
	prev *SockError
}

// Next returns the next error in the queue, or nil.
func (e *sockErrorEntry) Next() *SockError {
	return e.next
}

// sockErrorList is an intrusive doubly-linked list of *SockError.
type sockErrorList struct {
	head *SockError
	tail *SockError
}

// Front returns the first error, or nil if the queue is empty.
func (l *sockErrorList) Front() *SockError {
	return l.head
}

// PushBack appends err to the end of the queue.
func (l *sockErrorList) PushBack(err *SockError) {
	err.sockErrorEntry.next = nil
	err.sockErrorEntry.prev = l.tail
	if l.tail != nil {
		l.tail.sockErrorEntry.next = err
	} else {
		l.head = err
	}
	l.tail = err
}

// Remove unlinks err from the queue. err must be in the queue.
func (l *sockErrorList) Remove(err *SockError) {
	if err.sockErrorEntry.prev != nil {
		err.sockErrorEntry.prev.sockErrorEntry.next = err.sockErrorEntry.next
	} else {
		l.head = err.sockErrorEntry.next
	}
	if err.sockErrorEntry.next != nil {
		err.sockErrorEntry.next.sockErrorEntry.prev = err.sockErrorEntry.prev
	} else {
		l.tail = err.sockErrorEntry.prev
	}
	err.sockErrorEntry.next = nil
	err.sockErrorEntry.prev = nil
}

// Reset empties the queue.
func (l *sockErrorList) Reset() {
	l.head = nil
	l.tail = nil
}

// RouteEntry is the intrusive list element embedded in Route.
type RouteEntry struct {
	next *Route
	prev *Route
}

// Next returns the next route in the list, or nil.
func (e *RouteEntry) Next() *Route {
	return e.next
}

// RouteList is an intrusive doubly-linked list of *Route.
type RouteList struct {
	head *Route
	tail *Route
}

// Front returns the first route, or nil if the list is empty.
func (l *RouteList) Front() *Route {
	return l.head
}

// PushBack appends r to the end of the list.
func (l *RouteList) PushBack(r *Route) {
	r.RouteEntry.next = nil
	r.RouteEntry.prev = l.tail
	if l.tail != nil {
		l.tail.RouteEntry.next = r
	} else {
		l.head = r
	}
	l.tail = r
}

// InsertBefore inserts r immediately before existing, which must be in the list.
func (l *RouteList) InsertBefore(existing, r *Route) {
	r.RouteEntry.next = existing
	r.RouteEntry.prev = existing.RouteEntry.prev
	if existing.RouteEntry.prev != nil {
		existing.RouteEntry.prev.RouteEntry.next = r
	} else {
		l.head = r
	}
	existing.RouteEntry.prev = r
}

// Remove unlinks r from the list. r must be in the list.
func (l *RouteList) Remove(r *Route) {
	if r.RouteEntry.prev != nil {
		r.RouteEntry.prev.RouteEntry.next = r.RouteEntry.next
	} else {
		l.head = r.RouteEntry.next
	}
	if r.RouteEntry.next != nil {
		r.RouteEntry.next.RouteEntry.prev = r.RouteEntry.prev
	} else {
		l.tail = r.RouteEntry.prev
	}
	r.RouteEntry.next = nil
	r.RouteEntry.prev = nil
}

// Reset empties the list.
func (l *RouteList) Reset() {
	l.head = nil
	l.tail = nil
}
