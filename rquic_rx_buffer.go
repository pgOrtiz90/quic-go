// Inspired by ./internal/utils/linkedlist/linkedlist.go

package quic

import (
	"fmt"
	"time"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

const buffPacketThreshold uint8 = 3 // Same as packetThreshold

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
	fwd       *byte // reuses type field &p.data[rHdrPos+rquic.FieldPosType]
	id        *byte
	gid       *byte
	coeffLen  *byte
	rHdrPos   int
	delivered bool
	doNotFwd  bool
}

func (p *rQuicReceivedPacket) newerThan(other *rQuicReceivedPacket) bool { return rquic.IdLeftOlderEqRight(*other.id, *p.id) }
func (p *rQuicReceivedPacket) olderThan(other *rQuicReceivedPacket) bool { return rquic.IdLeftOlderEqRight(*p.id, *other.id) }

func (p *rQuicReceivedPacket) isObsolete() bool { return *p.fwd&rquic.FlagObsolete != 0 }
func (p *rQuicReceivedPacket) isSource() bool   { return *p.fwd&rquic.FlagSource != 0 }
func (p *rQuicReceivedPacket) wasCoded() bool   { return *p.fwd&rquic.FlagCoded != 0 }

func (p *rQuicReceivedPacket) pktType() string {
	if p.isSource() {
		if p.wasCoded() {
			return "REC"
		} else {
			return "SRC"
		}
	}
	return "COD"
}

func (p *rQuicReceivedPacket) pktInfo() string {
	return fmt.Sprintf("pkt.ID:%d pkt.Type:%s Obsolete:%t Delivered:%t ", *p.id, p.pktType(), p.isObsolete(), p.delivered)
}

func (p *rQuicReceivedPacket) isBetween() string {
	msg := fmt.Sprintf("pkt.ID:%d between ", *p.id)
	if o := p.getOlder(); o == nil {
		msg += "BOTTOM and "
	} else {
		msg += fmt.Sprintf("pkt.ID:%d and ", *o.id)
	}
	if n := p.getNewer(); n == nil {
		msg += "TOP "
	} else {
		msg += fmt.Sprintf("pkt.ID:%d ", *n.id)
	}
	return msg
}

func (p *rQuicReceivedPacket) isConsecutive() bool {
	nwstNotCons := *p.id - 2
	for o := p.getOlder(); o != nil; o = o.getOlder() {
		if rquic.IdLeftOlderEqRight(*o.id, nwstNotCons) {
			return false
		}
		if o.isSource() {
			// *p.id == *o.id => Repeated packet -> Decoder won't let this happen
			// *p.id == *o.id + 1
			return true
		}
	}
	return false
}

func (p *rQuicReceivedPacket) isHoldingBuffer() bool {
	if rquic.BTOOnly {
		return false
	}
	return rquic.IdLeftOlderEqRight(*p.gid, p.list.stragglerGen)
}

func (p *rQuicReceivedPacket) isWaitingTooLong(sRTT time.Duration) bool {
	theWait := p.list.timeOut
	alarm := p.rp.rcvTime.Add(theWait)
	rLogger.Debugf("Decoder Buffer Timeout:%v RcvTime:%v", theWait, p.rp.rcvTime.Format(rLogger.TimeOnly))
	if time.Now().After(alarm) {
		return true
	}
	p.list.setAlarm(alarm)
	return false
}

func (p *rQuicReceivedPacket) removeRQuicHeader() *receivedPacket {
	// Removing rQUIC header in e.rp.data will impair
	// further decoder's operations on this packet.
	rp := p.rp.Clone()
	bf := getPacketBuffer()
	bf.Data = bf.Data[:cap(bf.Data)]
	rp.buffer = bf
	rp.data = bf.Data

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

	// Get packet length and find 1st byte
	pos := p.rHdrPos + rquic.CodPreHeaderSize + int(*p.coeffLen) // [length] position
	pldLen := rquic.PldLenRead(p.rp.data, pos)
	pktEnd := p.rHdrPos + pldLen
	if len(rp.data) < pktEnd {
		panic("Recovered source packet is excessively big.")
	}
	pos += rquic.LenOfSrcLen // Decoded [1B] position

	// Copy data to the new packet
	if p.rHdrPos > 1 { // DCID.Len > 0
		rp.data[0] = p.rp.data[pos]
		rpLen++ // [1B] written
		rpLen += copy(rp.data[1:p.rHdrPos], p.rp.data[1:p.rHdrPos])
		pos++ // [ Protected payload... ] position
	}
	rpLen += copy(rp.data[rpLen:pktEnd], p.rp.data[pos:])
	for ; rpLen < pktEnd; rpLen++ {
		rp.data[rpLen] = 0
	}
	rp.data = rp.data[:pktEnd]

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

	stragglerGen         byte
	lastSeenGen          byte
	lastSeenGenOldestPkt byte
	givingChance2OoOPkts bool

	alarm           time.Time
	timeOut			time.Duration
}

// newRQuicReceivedPacketList returns an initialized list.
func newRQuicReceivedPacketList() *rQuicReceivedPacketList {
	return new(rQuicReceivedPacketList).init()
}

// Init initializes or clears list l.
func (l *rQuicReceivedPacketList) init() *rQuicReceivedPacketList {
	l.root.newer = &l.root
	l.root.older = &l.root
	l.root.list = l
	l.len = 0
	return l
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

func (l *rQuicReceivedPacketList) addNewReceivedPacket(p *receivedPacket, hdr *wire.Header) bool {
	// Add new packet to the buffer
	rHdrPos := 1 /*1st byte*/ + hdr.DestConnectionID.Len()
	fwd := &p.data[rHdrPos+rquic.FieldPosType]
	if *fwd & rquic.FlagObsolete != 0 /* is obsolete */ {
		return false
	}

	rqrp := &rQuicReceivedPacket{
		hdr:      hdr,
		rp:       p,
		fwd:      fwd,
		id:       &p.data[rHdrPos+rquic.FieldPosId],
		gid:      &p.data[rHdrPos+rquic.FieldPosGenId],
		coeffLen: &p.data[rHdrPos+rquic.FieldPosGenSize],
		rHdrPos:  rHdrPos,
	}

	// Update newest generation
	if rquic.IdLeftOlderRight(l.lastSeenGen, *rqrp.gid) {
		l.lastSeenGen = *rqrp.gid
		l.stragglerGen = l.lastSeenGen - 2
		l.givingChance2OoOPkts = true
	}
	if l.givingChance2OoOPkts && l.lastSeenGen == *rqrp.gid {
		// Update the oldest packet in the newest generation
		nwstGenOldestPkt := *rqrp.id
		if rqrp.wasCoded() {
			nwstGenOldestPkt += 1 - *rqrp.coeffLen
		}
		if rquic.IdLeftOlderRight(nwstGenOldestPkt, l.lastSeenGenOldestPkt) {
			l.lastSeenGenOldestPkt = nwstGenOldestPkt
		}
		// Update
		if rquic.IdLeftOlderEqRight(l.lastSeenGenOldestPkt + buffPacketThreshold, *rqrp.id) {
			// Time to release previous generation
			l.stragglerGen = *rqrp.gid - 1
			l.givingChance2OoOPkts = false
		}
	}

	return l.insertOrdered(rqrp) != nil
}

func (l *rQuicReceivedPacketList) insertOrdered(v *rQuicReceivedPacket) *rQuicReceivedPacket {
	for ref := l.newest(); ref != nil; ref = ref.getOlder() {
		if v.newerThan(ref) {
			return l.insert(v, ref)
		}
	}
	return l.insert(v, &l.root)
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
	rLogger.Debugf("Decoder Buffer Inserting %s", e.isBetween())
	return e
}

func (l *rQuicReceivedPacketList) order() {
	if rLogger.IsDebugging() {
		rLogger.Printf("Decoder Buffer Ordering started")
		defer rLogger.Printf("Decoder Buffer Ordering finished")
	}
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

// MoveBefore moves element e to its new position before mark.
// If e or mark is not an element of l, or e == mark, the list is not modified.
// The element and mark must not be nil.
func (l *rQuicReceivedPacketList) moveBefore(e, mark *rQuicReceivedPacket) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.insert(l.popout(e), mark.older)
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
		//rLogger.Debugf("Decoder Buffer PoppingOut pkt.ID:%d", *e.id)
	}
	return e
}

func (l *rQuicReceivedPacketList) remove(e *rQuicReceivedPacket) {
	l.popout(e)
	e.rp.buffer.Decrement()
	e.rp.buffer.MaybeRelease()
	//rLogger.Debugf("Decoder Buffer Removing "+e.pktInfo()+"IsObsolete:%t", e.isObsolete())
}

func (l *rQuicReceivedPacketList) setTimeoutDuration(maxAckDelay time.Duration) {
	l.timeOut = bufferTimeoutDuration(maxAckDelay)
}

func bufferTimeoutDuration(maxAckDelay time.Duration) time.Duration {
	// PTO = sRTT + max(4*RTTvar, TimerGranularity) + maxAckDelay >= sRTT + TimerGranularity + maxAckDelay
	// BTO = PTO_min - sRTT - Margin = TimerGranularity + maxAckDelay - Margin
	// Margin = TimerGranularity + ActualMargin
	// BTO = maxAckDelay - ActualMargin
	return utils.MaxDuration(maxAckDelay - time.Duration(rquic.BTOMargin) * protocol.TimerGranularity, protocol.TimerGranularity)
}

func (l *rQuicReceivedPacketList) setAlarm(alarm time.Time) {
	if l.alarm.IsZero() {
		l.alarm = alarm
		rLogger.Debugf("Decoder Buffer TimeoutAlarm Set:" + l.alarm.Format(rLogger.TimeOnly))
	}
}

func (l *rQuicReceivedPacketList) unsetAlarm() {
	if !l.alarm.IsZero() {
		rLogger.Debugf("Decoder Buffer TimeoutAlarm Unset")
	}
	l.alarm = time.Time{}
}
