// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated raw endpoint types.

package raw

// rawPacketEntry is the intrusive list element embedded in rawPacket.
type rawPacketEntry struct {
	next *rawPacket
	prev *rawPacket
}

// Next returns the next packet, or nil.
func (e *rawPacketEntry) Next() *rawPacket {
	return e.next
}

// rawPacketList is an intrusive doubly-linked list of *rawPacket.
type rawPacketList struct {
	head *rawPacket
	tail *rawPacket
}

// Front returns the first packet, or nil.
func (l *rawPacketList) Front() *rawPacket {
	return l.head
}

// Empty returns whether the list is empty.
func (l *rawPacketList) Empty() bool {
	return l.head == nil
}

// PushBack appends p to the list.
func (l *rawPacketList) PushBack(p *rawPacket) {
	p.rawPacketEntry.next = nil
	p.rawPacketEntry.prev = l.tail
	if l.tail != nil {
		l.tail.rawPacketEntry.next = p
	} else {
		l.head = p
	}
	l.tail = p
}

// Remove unlinks p from the list. p must be in the list.
func (l *rawPacketList) Remove(p *rawPacket) {
	if p.rawPacketEntry.prev != nil {
		p.rawPacketEntry.prev.rawPacketEntry.next = p.rawPacketEntry.next
	} else {
		l.head = p.rawPacketEntry.next
	}
	if p.rawPacketEntry.next != nil {
		p.rawPacketEntry.next.rawPacketEntry.prev = p.rawPacketEntry.prev
	} else {
		l.tail = p.rawPacketEntry.prev
	}
	p.rawPacketEntry.next = nil
	p.rawPacketEntry.prev = nil
}
