// Inspired by ./internal/utils/linkedlist/linkedlist.go

package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type rQuicReceivedPacket struct {
	// Newer and previous pointers in the doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.root is both the newer element of the last
	// list element (l.Newest()) and the previous element of the first list
	// element (l.Oldest()).
	newer, older *rQuicReceivedPacket

	// The list to which this element belongs.
	list *rQuicReceivedPacketList

	// Values
	hdr       *wire.Header
	rp        *receivedPacket
	id        *byte
	fwd       *byte
	coeffLen  *byte
	rHdrPos   int
	delivered bool
}

func (p *rQuicReceivedPacket) newerThan(other *rQuicReceivedPacket) bool { return *p.id-*other.id < 128 }
func (p *rQuicReceivedPacket) olderThan(other *rQuicReceivedPacket) bool { return *other.id-*p.id < 128 }

func (p *rQuicReceivedPacket) isObsolete() bool { return *p.fwd&rquic.FlagObsolete != 0 }
func (p *rQuicReceivedPacket) isSource() bool   { return *p.fwd&rquic.FlagSource != 0 }
func (p *rQuicReceivedPacket) wasCoded() bool   { return *p.fwd&rquic.FlagCoded != 0 }

func (p *rQuicReceivedPacket) removeRQuicHeader() *receivedPacket {
	// Removing rQUIC header in e.rp.data will impair
	// further decoder's operations on this packet.
	rp := p.rp.Clone()
	rp.buffer = getPacketBuffer()
	rp.data = rp.buffer.Slice

	var rpLen int

	// Remove rQUIC header from SRC
	// [1B][ DCID ][  rQUIC hdr   ][ Protected payload... ]  <--  p.rp.data
	// [1B][ DCID ]                [ Protected payload... ]  <--  rp.data
	if !p.wasCoded() {
		rpLen += copy(rp.data[:p.rHdrPos], p.rp.data[:p.rHdrPos])
		rpLen += copy(rp.data[p.rHdrPos:], p.rp.data[p.rHdrPos+rquic.SrcHeaderSize:])
		rp.data = rp.data[:rpLen]
		return rp
	}

	// Remove rQUIC header from decoded COD
	// [--][ DCID ][  rQUIC hdr   ][ Coefficients ][length][1B][ Protected payload... ]  <--  p.rp.data[pos]
	// [1B][ DCID ]                                            [ Protected payload... ]  <--  rp.data

	// Recover QUIC header and find packet length
	// [--][ DCID ][  rQUIC hdr   ][ Coefficients ][length][1B][
	// [1B][ DCID ]                                            [
	rpLen++ // Skip 1st Byte
	rpLen += copy(rp.data[1:p.rHdrPos], p.rp.data[1:p.rHdrPos])
	pos := p.rHdrPos + rquic.CodPreHeaderSize + int(*p.coeffLen) // [length] position
	pldLen := rquic.PldLenRead(p.rp.data, pos)
	pos += rquic.LenOfSrcLen // Decoded [1B] position
	rp.data[0] = p.rp.data[pos]
	pos++ // [ Protected payload... ] position

	// Check if decoded payload length exceeds the actual length
	pktEnd := rpLen + pldLen
	if len(rp.data) < pktEnd {
		panic("Recovered source packet is excessively big.")
	}

	// Copy protected payload
	rpLen += copy(rp.data[p.rHdrPos:pktEnd], p.rp.data[pos:protocol.MaxReceivePacketSize])
	for ; rpLen < pktEnd; rpLen++ {
		rp.data[rpLen] = 0
	}
	rp.data = rp.data[:rpLen]
	return rp
}

// Newer returns the newer list element or nil.
func (e *rQuicReceivedPacket) getNewer() *rQuicReceivedPacket {
	if p := e.newer; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// Older returns the previous list element or nil.
func (e *rQuicReceivedPacket) getOlder() *rQuicReceivedPacket {
	if p := e.older; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

func (e *rQuicReceivedPacket) shouldGoBefore(ref *rQuicReceivedPacket) bool {
	if ref == nil {
		return false
	}
	if e.list != ref.list {
		return false
	}
	// OLDEST -- ... -- ref.prv -- <e?> -- ref -- ... -- NEWEST
	if e.newerThan(ref) {
		return false
	}
	if prv := ref.getOlder(); prv != nil {
		return e.newerThan(prv)
	}
	return true
}

// rQuicReceivedPacketList is a linked list of RQuicReceivedPackets.
type rQuicReceivedPacketList struct {
	root rQuicReceivedPacket // sentinel list element, only &root, root.older, and root.newer are used
	len  int                 // current list length excluding (this) sentinel element
}

// Init initializes or clears list l.
func (l *rQuicReceivedPacketList) init() *rQuicReceivedPacketList {
	l.root.newer = &l.root
	l.root.older = &l.root
	l.root.list = l
	l.len = 0
	return l
}

// newRQuicReceivedPacketList returns an initialized list.
func newRQuicReceivedPacketList() *rQuicReceivedPacketList {
	return new(rQuicReceivedPacketList).init()
}

// Oldest returns the first element of list l or nil if the list is empty.
func (l *rQuicReceivedPacketList) oldest() *rQuicReceivedPacket {
	if l.len == 0 {
		return nil
	}
	return l.root.newer
}

// Newest returns the last element of list l or nil if the list is empty.
func (l *rQuicReceivedPacketList) newest() *rQuicReceivedPacket {
	if l.len == 0 {
		return nil
	}
	return l.root.older
}

// insert inserts e after at, increments l.len, and returns e.
func (l *rQuicReceivedPacketList) insert(e, at *rQuicReceivedPacket) *rQuicReceivedPacket {
	n := at.newer
	at.newer = e
	e.older = at
	e.newer = n
	n.older = e
	e.list = l
	l.len++
	return e
}

// popout removes e from l if e is an element of list l.
// It returns the element value e.
// The element must not be nil.
func (l *rQuicReceivedPacketList) popout(e *rQuicReceivedPacket) *rQuicReceivedPacket {
	if e.list == l {
		// if e.list == l, l must have been initialized when e was inserted
		// in l or l == nil (e is a zero Element) and l.remove will crash
		e.older.newer = e.newer
		e.newer.older = e.older
		e.newer = nil // avoid memory leaks
		e.older = nil // avoid memory leaks
		e.list = nil
		l.len--
		rLogger.Debugf("Decoder Buffer PoppingOut pkt.ID:%d", *e.id)
	}
	return e
}

func (l *rQuicReceivedPacketList) remove(e *rQuicReceivedPacket) *rQuicReceivedPacket {
	ePrev := e.older
	l.popout(e)
	e.rp.buffer.Decrement()
	e.rp.buffer.MaybeRelease()
	rLogger.Debugf("Decoder Buffer Removing pkt.ID:%d IsObsolete:%t IsSource:%t WasCoded:%t",
		*e.id, e.isObsolete(), e.isSource(), e.wasCoded(),
	)
	return ePrev
}

func (l *rQuicReceivedPacketList) insertOrdered(v *rQuicReceivedPacket) *rQuicReceivedPacket {
	for ref := l.newest(); ref != nil; ref = ref.getOlder() {
		if v.newerThan(ref) {
			return l.insert(v, ref)
		}
	}
	return l.insert(v, &l.root)
}

func (l *rQuicReceivedPacketList) addNewReceivedPacket(p *receivedPacket, hdr *wire.Header) {
	// Add new packet to the buffer
	rHdrPos := 1 /*1st byte*/ + hdr.DestConnectionID.Len()
	if p.data[rHdrPos+rquic.FieldPosType] & rquic.FlagObsolete != 0 /* is obsolete */ {
		return
	}
	rqrp := &rQuicReceivedPacket{
		hdr:      hdr,
		rp:       p,
		id:       &p.data[rHdrPos+rquic.FieldPosId],
		fwd:      &p.data[rHdrPos+rquic.FieldPosType],
		coeffLen: &p.data[rHdrPos+rquic.FieldPosGenSize],
		rHdrPos:  rHdrPos,
	}
	l.insertOrdered(rqrp)
}

// MoveBefore moves element e to its new position before mark.
// If e or mark is not an element of l, or e == mark, the list is not modified.
// The element and mark must not be nil.
func (l *rQuicReceivedPacketList) moveBefore(e, mark *rQuicReceivedPacket) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.insert(l.popout(e), mark.older)
}

func (l *rQuicReceivedPacketList) order() {
ScanLoop:
	for e := l.oldest().getNewer(); e != nil; e = e.getNewer() {
		if older := e.getOlder(); e.olderThan(older) {
			for np := older; np != nil; np = np.getOlder() {
				if e.shouldGoBefore(np) {
					l.moveBefore(e, np)
					continue ScanLoop
				}
			}
		}
	}
}
