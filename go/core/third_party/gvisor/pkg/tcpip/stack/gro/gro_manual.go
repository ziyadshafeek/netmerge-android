// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated GRO types.

package gro

// groPacketEntry is the intrusive list element embedded in groPacket.
type groPacketEntry struct {
	next *groPacket
	prev *groPacket
}

// Next returns the next packet, or nil.
func (e *groPacketEntry) Next() *groPacket {
	return e.next
}

// groPacketList is an intrusive doubly-linked list of *groPacket.
type groPacketList struct {
	head *groPacket
	tail *groPacket
}

// Front returns the first packet, or nil.
func (l *groPacketList) Front() *groPacket {
	return l.head
}

// PushBack appends p to the list.
func (l *groPacketList) PushBack(p *groPacket) {
	p.groPacketEntry.next = nil
	p.groPacketEntry.prev = l.tail
	if l.tail != nil {
		l.tail.groPacketEntry.next = p
	} else {
		l.head = p
	}
	l.tail = p
}

// Remove unlinks p from the list. p must be in the list.
func (l *groPacketList) Remove(p *groPacket) {
	if p.groPacketEntry.prev != nil {
		p.groPacketEntry.prev.groPacketEntry.next = p.groPacketEntry.next
	} else {
		l.head = p.groPacketEntry.next
	}
	if p.groPacketEntry.next != nil {
		p.groPacketEntry.next.groPacketEntry.prev = p.groPacketEntry.prev
	} else {
		l.tail = p.groPacketEntry.prev
	}
	p.groPacketEntry.next = nil
	p.groPacketEntry.prev = nil
}
