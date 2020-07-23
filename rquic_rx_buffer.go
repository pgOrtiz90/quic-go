// Inspired by ./internal/utils/linkedlist/linkedlist.go

package quic

import (
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

func (p *rQuicReceivedPacket) removeRQuicHeader() {
	pldEnd := len(p.rp.data)
	var pos int // will end up pointing at payload
	if p.wasCoded() {
		pos = p.rHdrPos + rquic.CodPreHeaderSize + int(*p.coeffLen) // length of decoded payload
		pldLen := rquic.PldLenRead(p.rp.data, pos)
		pos += rquic.LenOfSrcLen
		p.rp.data[0] = p.rp.data[pos] // recover decoded partially encrypted 1st byte
		pos += 1                      // decoded payload
		if newPldEnd := pos + pldLen; newPldEnd > pldEnd {
			// TODO: Stack overflow? Panic or close conn.
		} else {
			pldEnd = newPldEnd
		}
	} else {
		pos = p.rHdrPos + rquic.SrcHeaderSize
	}
	// Close the gap between 1st byte and DCID, and the payload
	posOrig := p.rHdrPos - 1
	posDest := pos
	for posOrig >= 0 {
		posDest--
		p.rp.data[posDest] = p.rp.data[posOrig]
		posOrig--
	}
	// posDest now is pointing at the beginning of the reconstructed QUIC packet
	p.rp.data = p.rp.data[posDest:pldEnd]
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

func (e *rQuicReceivedPacket) shouldGoAfter(ref *rQuicReceivedPacket) bool {
	if ref == nil {
		return false
	}
	if e.list != ref.list {
		return false
	}
	// OLDEST -- ... -- ref -- <e?> -- ref.nxt -- ... -- NEWEST
	if e.olderThan(ref) {
		return false
	}
	if nxt := ref.getNewer(); nxt != nil {
		return e.olderThan(nxt)
	}
	return true
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

// Remove removes e from l if e is an element of list l.
// It returns the element value e.
// The element must not be nil.
func (l *rQuicReceivedPacketList) remove(e *rQuicReceivedPacket) *rQuicReceivedPacket {
	if e.list == l {
		// if e.list == l, l must have been initialized when e was inserted
		// in l or l == nil (e is a zero Element) and l.remove will crash
		e.older.newer = e.newer
		e.newer.older = e.older
		e.newer = nil // avoid memory leaks
		e.older = nil // avoid memory leaks
		e.list = nil
		l.len--
	}
	rLogger.Debugf("Decoder Buffer Removing pkt.ID:%d IsObsolete:%t IsSource:%t WasCoded:%t",
		*e.id, e.isObsolete(), e.isSource(), e.wasCoded(),
	)
	return e
}

func (l *rQuicReceivedPacketList) insertOrdered(v *rQuicReceivedPacket) *rQuicReceivedPacket {
	for ref := l.newest(); ref != nil; ref = ref.getOlder() {
		if v.newerThan(ref) {
			return l.insert(v, ref.older)
		}
	}
	return l.insert(v, &l.root)
}

func (l *rQuicReceivedPacketList) addNewReceivedPacket(p *receivedPacket, hdr *wire.Header) {
	// Add new packet to the buffer
	rHdrPos := 1 /*1st byte*/ + hdr.DestConnectionID.Len()
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
	l.insert(l.remove(e), mark.older)
}

// MoveAfter moves element e to its new position after mark.
// If e or mark is not an element of l, or e == mark, the list is not modified.
// The element and mark must not be nil.
func (l *rQuicReceivedPacketList) moveAfter(e, mark *rQuicReceivedPacket) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.insert(l.remove(e), mark)
}

func (l *rQuicReceivedPacketList) order() {
ScanLoop:
	for e := l.oldest(); e != nil; e = e.getNewer() {
		//e.MaybeRecoverDecoded()
		if older := e.getOlder(); older != nil {
			if e.olderThan(older) {
				for np := older; np != nil; np = np.getOlder() {
					if e.shouldGoBefore(np) {
						l.moveBefore(e, np)
						continue ScanLoop
					}
				}
			}
		}
		if newer := e.getNewer(); newer != nil {
			if e.newerThan(newer) {
				for np := newer; np != nil; np = np.getNewer() {
					if e.shouldGoAfter(np) {
						l.moveAfter(e, np)
						continue ScanLoop
					}
				}
			}
		}
	}
}
