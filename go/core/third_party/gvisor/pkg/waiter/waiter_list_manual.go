// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated waiter list code
// (gVisor generates this from pkg/ilist templates at build time; the Go
// module does not ship it). Intrusive doubly-linked list of *Entry.

package waiter

// waiterEntry is the intrusive list element embedded in Entry.
type waiterEntry struct {
	next *Entry
	prev *Entry
}

// Next returns the next entry in the list, or nil.
func (e *waiterEntry) Next() *Entry {
	return e.next
}

// waiterList is an intrusive list of *Entry values.
type waiterList struct {
	head *Entry
	tail *Entry
}

// Front returns the first entry, or nil if the list is empty.
func (l *waiterList) Front() *Entry {
	return l.head
}

// PushBack appends e to the end of the list. e must not already be in a list.
func (l *waiterList) PushBack(e *Entry) {
	e.waiterEntry.next = nil
	e.waiterEntry.prev = l.tail
	if l.tail != nil {
		l.tail.waiterEntry.next = e
	} else {
		l.head = e
	}
	l.tail = e
}

// Remove unlinks e from the list. e must be in the list.
func (l *waiterList) Remove(e *Entry) {
	if e.waiterEntry.prev != nil {
		e.waiterEntry.prev.waiterEntry.next = e.waiterEntry.next
	} else {
		l.head = e.waiterEntry.next
	}
	if e.waiterEntry.next != nil {
		e.waiterEntry.next.waiterEntry.prev = e.waiterEntry.prev
	} else {
		l.tail = e.waiterEntry.prev
	}
	e.waiterEntry.next = nil
	e.waiterEntry.prev = nil
}
