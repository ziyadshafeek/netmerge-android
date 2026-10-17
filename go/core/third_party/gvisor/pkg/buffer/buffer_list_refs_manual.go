// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated buffer list/refcount
// code (gVisor generates these from pkg/ilist and pkg/refs templates at
// build time; the Go module does not ship them).

package buffer

import "sync/atomic"

// ViewEntry is the intrusive list element embedded in View.
type ViewEntry struct {
	next *View
	prev *View
}

// Next returns the next view in the list, or nil.
func (e *ViewEntry) Next() *View {
	return e.next
}

// Prev returns the previous view in the list, or nil.
func (e *ViewEntry) Prev() *View {
	return e.prev
}

// ViewList is an intrusive doubly-linked list of *View.
type ViewList struct {
	head *View
	tail *View
	size int
}

// Front returns the first view, or nil if empty.
func (l *ViewList) Front() *View {
	return l.head
}

// Back returns the last view, or nil if empty.
func (l *ViewList) Back() *View {
	return l.tail
}

// Len returns the number of views in the list.
func (l *ViewList) Len() int {
	return l.size
}

// PushBack appends v to the end of the list.
func (l *ViewList) PushBack(v *View) {
	v.ViewEntry.next = nil
	v.ViewEntry.prev = l.tail
	if l.tail != nil {
		l.tail.ViewEntry.next = v
	} else {
		l.head = v
	}
	l.tail = v
	l.size++
}

// PushFront prepends v to the start of the list.
func (l *ViewList) PushFront(v *View) {
	v.ViewEntry.prev = nil
	v.ViewEntry.next = l.head
	if l.head != nil {
		l.head.ViewEntry.prev = v
	} else {
		l.tail = v
	}
	l.head = v
	l.size++
}

// InsertBefore inserts v immediately before existing, which must be in the list.
func (l *ViewList) InsertBefore(existing, v *View) {
	v.ViewEntry.next = existing
	v.ViewEntry.prev = existing.ViewEntry.prev
	if existing.ViewEntry.prev != nil {
		existing.ViewEntry.prev.ViewEntry.next = v
	} else {
		l.head = v
	}
	existing.ViewEntry.prev = v
	l.size++
}

// Remove unlinks v from the list. v must be in the list.
func (l *ViewList) Remove(v *View) {
	if v.ViewEntry.prev != nil {
		v.ViewEntry.prev.ViewEntry.next = v.ViewEntry.next
	} else {
		l.head = v.ViewEntry.next
	}
	if v.ViewEntry.next != nil {
		v.ViewEntry.next.ViewEntry.prev = v.ViewEntry.prev
	} else {
		l.tail = v.ViewEntry.prev
	}
	v.ViewEntry.next = nil
	v.ViewEntry.prev = nil
	l.size--
}

// PushBackList appends all views of other to the end of l, emptying other.
func (l *ViewList) PushBackList(other *ViewList) {
	if other.head == nil {
		return
	}
	if l.tail == nil {
		l.head = other.head
	} else {
		l.tail.ViewEntry.next = other.head
		other.head.ViewEntry.prev = l.tail
	}
	l.tail = other.tail
	l.size += other.size
	other.head = nil
	other.tail = nil
	other.size = 0
}

// chunkRefs is the intrusive reference count embedded in chunk.
type chunkRefs struct {
	refCount atomic.Int64
}

// InitRefs initializes the reference count to 1.
func (r *chunkRefs) InitRefs() {
	r.refCount.Store(1)
}

// IncRef increments the reference count.
func (r *chunkRefs) IncRef() {
	r.refCount.Add(1)
}

// DecRef decrements the reference count, calling destroy when it reaches zero.
func (r *chunkRefs) DecRef(destroy func()) {
	if r.refCount.Add(-1) == 0 {
		destroy()
	}
}
