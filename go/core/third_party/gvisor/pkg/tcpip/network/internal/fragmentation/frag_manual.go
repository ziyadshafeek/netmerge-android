// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated fragmentation types.

package fragmentation

// reassemblerEntry is the intrusive list element embedded in reassembler.
type reassemblerEntry struct {
	next *reassembler
	prev *reassembler
}

// Next returns the next reassembler, or nil.
func (e *reassemblerEntry) Next() *reassembler {
	return e.next
}

// reassemblerList is an intrusive doubly-linked list of *reassembler.
type reassemblerList struct {
	head *reassembler
	tail *reassembler
}

// Front returns the first reassembler, or nil.
func (l *reassemblerList) Front() *reassembler {
	return l.head
}

// Back returns the last reassembler, or nil.
func (l *reassemblerList) Back() *reassembler {
	return l.tail
}

// Empty returns whether the list is empty.
func (l *reassemblerList) Empty() bool {
	return l.head == nil
}

// PushFront prepends r to the list.
func (l *reassemblerList) PushFront(r *reassembler) {
	r.reassemblerEntry.prev = nil
	r.reassemblerEntry.next = l.head
	if l.head != nil {
		l.head.reassemblerEntry.prev = r
	} else {
		l.tail = r
	}
	l.head = r
}

// Remove unlinks r from the list. r must be in the list.
func (l *reassemblerList) Remove(r *reassembler) {
	if r.reassemblerEntry.prev != nil {
		r.reassemblerEntry.prev.reassemblerEntry.next = r.reassemblerEntry.next
	} else {
		l.head = r.reassemblerEntry.next
	}
	if r.reassemblerEntry.next != nil {
		r.reassemblerEntry.next.reassemblerEntry.prev = r.reassemblerEntry.prev
	} else {
		l.tail = r.reassemblerEntry.prev
	}
	r.reassemblerEntry.next = nil
	r.reassemblerEntry.prev = nil
}
