package quic

import (
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

func (e *encoder) offset() int { return 1 /*1st byte*/ + e.lenDCID }

func (e *encoder) process(p *packedPacket) []*packedPacket {
	if e.doNotEncode {
		e.processUnprotected(p)
		return []*packedPacket{}
	}

	e.newCodedPackets = []*packedPacket{}
	e.checkDCID(p.header.DestConnectionID.Bytes())

	// Add rQUIC header to SRC. Prepare SRC for coding if necessary.
	if !p.IsAckEliciting() { // Not protected
		e.processUnprotected(p)
		return e.newCodedPackets
	}
	e.processProtected(p.raw)
	e.ratio.AddTxCount()

	// Add SRC to the CODs under construction

	e.firstByte = p.raw[0] & 0xd0 // only unprotected bits

	for i, rb := range e.redunBuilders {
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

func (e *encoder) processUnprotected(p *packedPacket) {
	ofs := e.offset()
	pldPos := ofs + rquic.FieldSizeType

	//////// Move unencrypted part of the header to the beginning
	// [  0   0   0   0 ][1stB][      DCID      ][ PN ][ Payload ]
	// XXXXXXXXXXXXX|<---[======================]
	p.raw = p.raw[rquic.SrcHeaderSize-rquic.FieldSizeType:]
	copy(p.raw, p.raw[rquic.FieldSizeType:pldPos])

	// [1stB][      DCID      ][  ? ][ PN ][ Payload ]
	//                         [Type]
	p.raw[ofs] = rquic.TypeUnprotected

	rLogger.Debugf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X  % X]",
		len(p.raw), e.lenDCID, p.raw[:ofs], p.raw[ofs:pldPos],
	)
}

func (e *encoder) processProtected(raw []byte) {
	ofs := e.offset()

	//////// Move unencrypted part of the header to the beginning
	// [  0   0   0   0 ][1stB][      DCID      ][ PN ][ Payload ]
	// |<---- copy  -----[======================]
	copy(raw, raw[rquic.SrcHeaderSize:rquic.SrcHeaderSize+ofs])

	//////// Complete rQUIC header
	pldPos := ofs + rquic.SrcHeaderSize
	raw[ofs+rquic.FieldPosType] = rquic.TypeProtected
	raw[ofs+rquic.FieldPosId] = e.rQuicId
	raw[ofs+rquic.FieldPosLastGen] = e.rQuicGenId
	raw[ofs+rquic.FieldPosOverlap] = byte(len(e.redunBuilders)) // e.overlap
	rLogger.Debugf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X  % X]",
		len(raw), e.lenDCID, raw[:ofs], raw[ofs:pldPos],
	)

	//////// Prepare SRC to be coded
	e.srcForCoding = e.srcForCoding[:cap(e.srcForCoding)]
	// [  len(what remains)   ][          ][          ]
	lng := rquic.LenOfSrcLen
	copy(e.srcForCoding[:lng], rquic.PldLenPrepare(len(raw)-pldPos))
	// [          ][          ][ 1st Byte ][          ]
	e.srcForCoding[lng] = raw[0]
	// [          ][          ][          ][ packet.number, packet.payload...
	lng++
	lng += copy(e.srcForCoding[lng:], raw[pldPos:])
	// Limit packet to its length
	e.srcForCoding = e.srcForCoding[:lng]
}

func (e *encoder) checkDCID(newDCID []byte) {
	if bytes.Equal(e.currentDCID, newDCID) {
		return
	}
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	e.currentDCID = append(newDCID[0:0], newDCID...)
	e.lenDCID = len(newDCID)
	e.redunBuildersPurge()
	e.redunBuildersInit()
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
		builder:    schemes.MakeRedunBuilder(e.scheme, packets, e.offset()),
		buffers:    bfs,
		rateScaler: e.overlapF64,
	}
}

func (e *encoder) assemble(rb *redunBuilder) {
	coeffsLen, codLen := rb.builder.Finish()
	if codLen == 0 {
		return
	} // No SRC, no COD, nothing to assemble

	var pdPkt packedPacket
	var lastElem int
	rQHdrPos := rb.builder.RHdrPos()
	rQPldPos := rQHdrPos + rquic.CodPreHeaderSize + coeffsLen
	unused := rb.builder.UnusedCoeffSpace()
	fieldPosId := rQHdrPos + rquic.FieldPosId
	fieldPosGenId := rQHdrPos + rquic.FieldPosGenId

	for _, bf := range rb.buffers {

		// sendQueue (send_queue.go) only uses p.raw and p.buffer.Release()
		pdPkt = packedPacket{buffer: bf}
		pdPkt.raw = bf.Slice[unused:rQPldPos+codLen] // rb.builder.Finish has already shifted the header to payload.
		// After linear combination, last useful bytes might become 0. Decoder can handle a packet without them.
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
			rCPos := rQHdrPos + rquic.CodPreHeaderSize
			rLogger.Printf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X  % X  % X  % X]",
				len(pdPkt.raw), e.lenDCID,
				pdPkt.raw[:rQHdrPos],
				pdPkt.raw[rQHdrPos:rCPos],
				pdPkt.raw[rCPos:rQPldPos],
				pdPkt.raw[rQPldPos:rQPldPos+rquic.CodedOverhead],
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

	rLogger.Logf("Encoder Ratio MinPktsCWND:%f CurrentRatio:%f RatioChanged:%t", newRatio, curRatio, doChange)

	if doChange {
		e.ratio.Change(newRatio)
	}
	return doChange
}

// disableCoding stops generating coded packets,
// but does not disable rQUIC
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

func MakeEncoder(conf *rquic.CConf) *encoder {
	rLogger.Logf("Encoder New %+v", conf)
	dynRatio := rencoder.MakeRatio(
		conf.RatioVal,
		conf.Dynamic > 0,
		conf.TPeriod,
		conf.NumPeriods,
		conf.GammaTarget,
		conf.DeltaRatio,
	)
	enc := &encoder{
		ratio:        dynRatio,
		scheme:       conf.Scheme,
		overlap:      byte(conf.Overlap),
		overlapInt:   conf.Overlap,
		reduns:       conf.Reduns,
		srcForCoding: make([]byte, protocol.MaxPacketSizeIPv4),
	}
	enc.redunBuildersInit()
	rquic.SeedFieldMaxSizeUpdate(int(enc.redunBuilders[0].builder.SeedMaxFieldSize()))
	return enc
}
