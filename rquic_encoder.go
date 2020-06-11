package quic

import (
	"time"
	"bytes"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/schemes"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic/rencoder"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type redunBuilder struct {
	builder    schemes.RedunBuilder
	buffers    []*packetBuffer
	firstId    byte
	rateScaler float64
}

func (r *redunBuilder) readyToSend(ratio float64) bool {
	// Every genSize/overlap reduns packets are sent --> ratio = genSize/(overlap*reduns)
	// Check genSize/reduns > ratio * overlap
	// The first generations are partial, ratio is not always multiplied with overlap
	return r.builder.ReadyToSend(ratio * r.rateScaler)
}

type encoder struct {
	rQuicId    uint8
	rQuicGenId uint8

	firstByte   uint8
	lenDCID     int
	currentDCID []byte

	ratio      rencoder.DynRatio
	scheme     uint8
	overlap    uint8 // overlapping generations, i.e. convolutional
	overlapInt int
	overlapF64 float64
	reduns     int

	redunBuilders   []*redunBuilder
	srcForCoding    []byte
	newCodedPackets []*packedPacket

	doNotEncode     bool
	ratioWasDynamic bool
}

func (e *encoder) lenNotProtected() int { return e.lenDCID + rquic.SrcHeaderSize }
func (e *encoder) rQuicHdrPos() int     { return 1 /*1st byte*/ + e.lenDCID }
func (e *encoder) rQuicSrcPldPos() int  { return 1 /*1st byte*/ + e.lenDCID + rquic.SrcHeaderSize }

func (e *encoder) process(pdSrc *packedPacket) []*packedPacket {
	if e.doNotEncode {
		return []*packedPacket{}
	}

	dcid := pdSrc.header.DestConnectionID.Bytes()
	e.lenDCID = len(dcid)
	e.firstByte = pdSrc.raw[0]
	e.addTransmissionCount()
	e.newCodedPackets = []*packedPacket{}

	rQuicHdrPos := e.rQuicHdrPos()
	rQuicSrcPldPos := e.rQuicSrcPldPos()

	// Check QUIC header and the space reserved for rQUIC header
	if rLogger.IsDebugging() {
		wrongHeader := e.firstByte == 0 && !bytes.Equal(pdSrc.raw[1:rQuicHdrPos], dcid)
		for i := rQuicHdrPos; !wrongHeader && i < rQuicSrcPldPos; i++ {
			wrongHeader = pdSrc.raw[i] != 0
		}
		if wrongHeader {
			rLogger.Printf("ERROR Encoder Header Malformed DCID.Len:%d rQUIChdr.Len:%d hdr(hex):[% X]",
				e.lenDCID, rquic.SrcHeaderSize, pdSrc.raw[:rQuicSrcPldPos+1],
			)
		}
	}

	// Add rQUIC header to SRC. Prepare SRC for coding if necessary.
	if !pdSrc.IsAckEliciting() { // Not protected
		posTypeNew := e.rQuicSrcPldPos() - 1
		pdSrc.raw[posTypeNew] = 0
		copy(pdSrc.raw[rquic.ProtMinusUnprotLen:posTypeNew], pdSrc.raw[:rQuicHdrPos])
		pdSrc.raw = pdSrc.raw[rquic.ProtMinusUnprotLen:]
		if rLogger.IsDebugging() {
			rLogger.Printf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X]",
				len(pdSrc.raw), e.lenDCID, pdSrc.raw[:rQuicHdrPos+rquic.FieldSizeTypeScheme],
			)
		}
		return e.newCodedPackets
	}
	e.processProtected(pdSrc.raw)

	// Add SRC to the CODs under construction

	e.checkDCID(dcid)
	var rb *redunBuilder

	for i := 0; i < len(e.redunBuilders); i++ {
		rb = e.redunBuilders[i]
		rb.builder.AddSrc(e.srcForCoding)
		if rb.readyToSend(e.ratio.Check()) {
			e.assemble(rb)
			e.rQuicGenId++
			e.redunBuilders[i] = e.redunBuildersNew()
		}
	}

	rLogger.MaybeIncreaseTxSrc()
	if cods := len(e.newCodedPackets); cods > 0 {
		rLogger.MaybeIncreaseTxCodN(cods)
	}

	e.rQuicId++ // TODO: consider adding a random number
	return e.newCodedPackets
}

func (e *encoder) processProtected(raw []byte) {
	//////// Complete rQUIC header
	ofs := e.rQuicHdrPos()
	pldPos := e.rQuicSrcPldPos()
	raw[ofs+rquic.FieldPosTypeScheme] = rquic.MaskType | e.scheme // Sending current scheme (unencrypted!) for debugging
	raw[ofs+rquic.FieldPosId] = e.rQuicId
	raw[ofs+rquic.FieldPosLastGen] = e.rQuicGenId
	raw[ofs+rquic.FieldPosOverlap] = e.overlap
	if rLogger.IsDebugging() {
		rLogger.Printf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X]",
			len(raw), e.lenDCID, raw[:ofs+pldPos],
		)
	}

	//////// Prepare SRC to be coded
	e.srcForCoding = e.srcForCoding[:cap(e.srcForCoding)]
	// [  len(what remains)   ][          ][          ]
	lng := rquic.LenOfSrcLen
	copy(e.srcForCoding[:lng], rquic.PldLenPrepare(len(raw)-e.lenNotProtected()))
	// [          ][          ][ 1st Byte ][          ]
	e.srcForCoding[lng] = raw[0]
	// [          ][          ][          ][ packet.number, packet.payload...
	lng++
	lng += copy(e.srcForCoding[lng:], raw[pldPos:])
	// Limit packet to its length
	e.srcForCoding = e.srcForCoding[:lng]
}

func (e *encoder) checkDCID(newDCID []byte) {
	if e.currentDCID != nil {
		if !bytes.Equal(e.currentDCID, newDCID) {
			// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
			e.currentDCID = append(newDCID[0:0], newDCID...)
			e.redunBuildersPurge()
			e.redunBuildersInit()
		}
	} else {
		e.currentDCID = append(newDCID[0:0], newDCID...)
	}
}

func (e *encoder) redunBuildersPurge() {
	for i, rb := range e.redunBuilders {
		e.assemble(rb)
		e.redunBuilders[i] = nil
	}
	e.redunBuilders = e.redunBuilders[:0]
}

func (e *encoder) redunBuildersInit() {
	e.overlapF64 = 0
	for i := 0; i < e.overlapInt; i++ {
		e.overlapF64++
		e.redunBuilders = append(e.redunBuilders, e.redunBuildersNew())
	}
}

func (e *encoder) redunBuildersNew() *redunBuilder {
	var bfs []*packetBuffer
	var bf *packetBuffer
	var packets [][]byte
	for i := 0; i < e.reduns; i++ {
		bf = getPacketBuffer()
		bfs = append(bfs, bf)
		packets = append(packets, bf.Slice)
	}
	return &redunBuilder{
		builder:    schemes.MakeRedunBuilder(e.scheme, packets, e.rQuicHdrPos()),
		buffers:    bfs,
		firstId:    e.rQuicId,
		rateScaler: e.overlapF64,
	}
}

func (e *encoder) assemble(rb *redunBuilder) {
	rb.builder.Finish()

	var pdPkt packedPacket
	var ofs int
	var lastElem int
	rQHdrPos := e.rQuicHdrPos()
	fieldPosId := rQHdrPos + rquic.FieldPosId
	fieldPosGenId := rQHdrPos + rquic.FieldPosGenId

	for _, bf := range rb.buffers {

		// sendQueue (send_queue.go) only uses p.raw and p.buffer.Release()
		pdPkt = packedPacket{buffer: bf}
		ofs = int(bf.Slice[0])
		pdPkt.raw = bf.Slice[ofs:]
		// After linear combination, last useful bytes might become 0. Decoder can handle this.
		lastElem = len(pdPkt.raw) - 1
		for pdPkt.raw[lastElem] == 0 {
			lastElem--
		}
		pdPkt.raw = pdPkt.raw[:lastElem+1]

		// Complete rQUIC header
		pdPkt.raw[0] = e.firstByte
		copy(pdPkt.raw[1:rQHdrPos], e.currentDCID)
		pdPkt.raw[fieldPosId] = e.rQuicId
		pdPkt.raw[fieldPosGenId] = e.rQuicGenId

		// Add packet to the assembled packet list
		e.newCodedPackets = append(e.newCodedPackets, &pdPkt)

		if rLogger.IsDebugging() {
			rLogger.Printf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X]",
				len(pdPkt.raw), e.lenDCID, pdPkt.raw[:rQHdrPos+rquic.CodHeaderSizeMax],
			)
		}
	}
}

// updateRQuicOverhead has to be called whenever a coding scheme is changed
func (e *encoder) updateRQuicOverhead() {
	var sizeSeedCoeff int
	for _, rb := range e.redunBuilders {
		sizeSeedCoeff = utils.Max(sizeSeedCoeff, int(rb.builder.SeedMaxFieldSize()))
	}
	rquic.SeedFieldMaxSizeUpdate(sizeSeedCoeff)
}

func (e *encoder) maybeReduceCodingRatio(minPktsCwnd protocol.ByteCount) bool /* did reduce ratio */ {
	curRatio := e.ratio.Check()
	newRatio := float64(minPktsCwnd)
	doChange := newRatio < curRatio

	if rLogger.IsEnabled() {
		rLogger.Printf("Encoder Ratio MinPktsCWND:%f CurrentRatio:%f RatioChanged:%t", newRatio, curRatio, doChange)
	}

	if doChange {
		e.ratio.Change(newRatio)
	}
	return doChange
}

func (e *encoder) disableCoding() {
	e.redunBuildersPurge()
	e.ratioWasDynamic = e.ratio.IsDynamic()
	e.ratio.MakeStatic()
	e.doNotEncode = true
}

func (e *encoder) enableCoding() {
	e.doNotEncode = false
	e.redunBuildersInit()
	if e.ratioWasDynamic {
		e.ratio.MakeDynamic()
	}
}

func (e *encoder) updateUnAcked(loss, unAcked int) {
	e.ratio.UpdateUnAcked(loss, unAcked)
}

func (e *encoder) addTransmissionCount() {
	e.ratio.AddTxCount()
}

func MakeEncoder(
	scheme uint8,
	overlap int,
	reduns  int,
	dynamic bool,
	Tperiod time.Duration,
	numPeriods int,
	gammaTarget float64,
	deltaRatio float64,
) *encoder {

	enc := &encoder{
		ratio:        rencoder.MakeRatio(dynamic, Tperiod, numPeriods, gammaTarget, deltaRatio),
		scheme:       scheme,
		overlap:      byte(overlap), // Currently, given the overlap and redunancies
		overlapInt:   overlap,       // per generation, we only change generation size.
		reduns:       reduns,        // Overlap and redundancies variation are WiP
		srcForCoding: make([]byte, protocol.MaxPacketSizeIPv4),
	}

	enc.redunBuildersInit()
	rquic.SeedFieldMaxSizeUpdate(int(enc.redunBuilders[0].builder.SeedMaxFieldSize()))

	return enc
}
