// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated UDP types.

package udp

// udpPacketEntry is the intrusive list element embedded in udpPacket.
type udpPacketEntry struct {
	next *udpPacket
	prev *udpPacket
}

// Next returns the next packet, or nil.
func (e *udpPacketEntry) Next() *udpPacket {
	return e.next
}

// udpPacketList is an intrusive doubly-linked list of *udpPacket.
type udpPacketList struct {
	head *udpPacket
	tail *udpPacket
}

// Front returns the first packet, or nil.
func (l *udpPacketList) Front() *udpPacket {
	return l.head
}

// Empty returns whether the list is empty.
func (l *udpPacketList) Empty() bool {
	return l.head == nil
}

// PushBack appends p to the list.
func (l *udpPacketList) PushBack(p *udpPacket) {
	p.udpPacketEntry.next = nil
	p.udpPacketEntry.prev = l.tail
	if l.tail != nil {
		l.tail.udpPacketEntry.next = p
	} else {
		l.head = p
	}
	l.tail = p
}

// Remove unlinks p from the list. p must be in the list.
func (l *udpPacketList) Remove(p *udpPacket) {
	if p.udpPacketEntry.prev != nil {
		p.udpPacketEntry.prev.udpPacketEntry.next = p.udpPacketEntry.next
	} else {
		l.head = p.udpPacketEntry.next
	}
	if p.udpPacketEntry.next != nil {
		p.udpPacketEntry.next.udpPacketEntry.prev = p.udpPacketEntry.prev
	} else {
		l.tail = p.udpPacketEntry.prev
	}
	p.udpPacketEntry.next = nil
	p.udpPacketEntry.prev = nil
}
