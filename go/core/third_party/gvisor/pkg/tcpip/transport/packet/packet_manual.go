// Copyright 2026 The NetMerge Authors.
// Hand-written replacement for the Bazel-generated packet endpoint types.

package packet

import "sync"

// packetEntry is the intrusive list element embedded in packet.
type packetEntry struct {
	next *packet
	prev *packet
}

// Next returns the next packet, or nil.
func (e *packetEntry) Next() *packet {
	return e.next
}

// packetList is an intrusive doubly-linked list of *packet.
type packetList struct {
	head *packet
	tail *packet
}

// Front returns the first packet, or nil.
func (l *packetList) Front() *packet {
	return l.head
}

// Empty returns whether the list is empty.
func (l *packetList) Empty() bool {
	return l.head == nil
}

// PushBack appends p to the list.
func (l *packetList) PushBack(p *packet) {
	p.packetEntry.next = nil
	p.packetEntry.prev = l.tail
	if l.tail != nil {
		l.tail.packetEntry.next = p
	} else {
		l.head = p
	}
	l.tail = p
}

// Remove unlinks p from the list. p must be in the list.
func (l *packetList) Remove(p *packet) {
	if p.packetEntry.prev != nil {
		p.packetEntry.prev.packetEntry.next = p.packetEntry.next
	} else {
		l.head = p.packetEntry.next
	}
	if p.packetEntry.next != nil {
		p.packetEntry.next.packetEntry.prev = p.packetEntry.prev
	} else {
		l.tail = p.packetEntry.prev
	}
	p.packetEntry.next = nil
	p.packetEntry.prev = nil
}

type rcvMutex struct{ sync.Mutex }
type packetMmapRWMutex struct{ sync.RWMutex }
type lastErrorMutex struct{ sync.Mutex }
type endpointRWMutex struct{ sync.RWMutex }
