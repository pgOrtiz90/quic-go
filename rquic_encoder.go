package quic

import (
	"bytes"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/schemes"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic/rencoder"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"time"
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

	ratio       *rencoder.DynRatio
	scheme      uint8
	overlap     uint8 // overlapping generations, i.e. convolutional
	overlapInt  int
	overlapF64  float64
	reduns      int

	redunBuilders   []*redunBuilder
	srcForCoding    []byte
	newCodedPackets []*packetBuffer

	getCongestionWindow func() protocol.ByteCount
	smoothedRTT         func() time.Duration
	localMaxAckDelay    time.Duration

	encodingPaused  bool
	ratioWasDynamic bool
}

func (e *encoder) offset() int { return 1 /*1st byte*/ + e.lenDCID }

func (e *encoder) process(p []byte, dcid []byte, ackEliciting bool) {
	e.maybeReduceCodingRatio()
	e.checkDCID(dcid)

	// Protect only ACK eliciting packets
	if !ackEliciting { // Not protected
		e.processUnprotected(p)
		return
	}

	// SRC packet
	rLogger.MaybeIncreaseTxSrc()
	if e.encodingPaused { // Stop encoding if coding ratio is getting too big
		e.processUnprotected(p)
		return
	}
	e.processProtected(p)

	// Add SRC to the CODs under construction

	e.firstByte = p[0] & 0xe0 // only unprotected bits

	for i, rb := range e.redunBuilders {
		rb.builder.AddSrc(e.srcForCoding)
		if rb.readyToSend(e.ratio.Check()) {
			e.assemble(rb)
			e.rQuicGenId++
			e.redunBuilders[i] = e.redunBuildersNew()
		}
	}

	e.rQuicId++ // Current ID is already used by at least SRC
}

func (e *encoder) processUnprotected(p []byte) {
	ofs := e.offset()
	pldPos := ofs + rquic.FieldSizeType

	//////// Move unencrypted part of the header to the beginning
	// [  0 ][1stB][      DCID      ][ PN ][ Payload ]
	// |<----[======================]
	copy(p, p[rquic.FieldSizeType:pldPos])

	// [1stB][      DCID      ][  ? ][ PN ][ Payload ]
	//                         [Type]
	p[ofs] = rquic.TypeUnprotected

	rLogger.Debugf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X  % X]",
		len(p), e.lenDCID, p[:ofs], p[ofs:pldPos],
	)
}

func (e *encoder) processProtected(p []byte) {
	ofs := e.offset()

	//////// Move unencrypted part of the header to the beginning
	// [  0   0   0   0 ][1stB][      DCID      ][ PN ][ Payload ]
	// |<---- copy  -----[======================]
	copy(p, p[rquic.SrcHeaderSize:rquic.SrcHeaderSize+ofs])

	//////// Complete rQUIC header
	pldPos := ofs + rquic.SrcHeaderSize
	p[ofs+rquic.FieldPosType] = rquic.TypeProtected
	p[ofs+rquic.FieldPosId] = e.rQuicId
	p[ofs+rquic.FieldPosLastGen] = e.rQuicGenId
	p[ofs+rquic.FieldPosOverlap] = byte(len(e.redunBuilders)) // e.overlap
	rLogger.Debugf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X  % X]",
		len(p), e.lenDCID, p[:ofs], p[ofs:pldPos],
	)

	//////// Prepare SRC to be coded
	e.srcForCoding = e.srcForCoding[:cap(e.srcForCoding)]
	// [  len(protected pld)  ][          ][          ]
	lng := rquic.LenOfSrcLen
	copy(e.srcForCoding[:lng], rquic.PldLenPrepare(len(p)-pldPos))
	// [          ][          ][ 1st Byte ][          ]
	e.srcForCoding[lng] = p[0]
	// [          ][          ][          ][ packet.number, packet.payload...
	lng++
	lng += copy(e.srcForCoding[lng:], p[pldPos:])
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
	if e.encodingPaused {
		return
	}
	e.redunBuildersPurge()
	e.redunBuildersInit()
}

func (e *encoder) encodingNotPaused() (doEncode bool) {
	switch rquic.PauseEncodingWith {
	case rquic.PauseEncodingNever:
		doEncode = true
	case rquic.PauseEncodingTillFirstLoss:
		doEncode = !e.encodingPaused || e.ratio.ResLossAppreciable()
	case rquic.PauseEncodingWithResidualLoss:
		doEncode = e.ratio.ResLossAppreciable()
	default:
		rquic.PauseEncodingWith = rquic.PauseEncodingNever
		doEncode = true
	}
	if doEncode {
		if !e.encodingPaused {
			return
		}
		// e.encodingPaused == true, resume
		e.redunBuildersInit()
		e.encodingPaused = false
		rLogger.Debugf("Encoder Encoding Resumed Criterion:" + rquic.PauseEncodingExplained())
		return
	} // else
	if e.encodingPaused {
		return
	}
	// encoding enabled, pause it
	e.redunBuildersSilentRelease()
	e.newCodedPackets = e.newCodedPackets[:0]
	e.encodingPaused = true
	rLogger.Debugf("Encoder Encoding Paused Criterion:" + rquic.PauseEncodingExplained())
	return
}

func (e *encoder) redunBuildersSilentRelease() {
	// Get rid of redunBuilders without assembling and sending coded packets
	for i, rb := range e.redunBuilders {
		for _, p := range rb.buffers {
			p.Release()
		}
		e.redunBuilders[i] = nil
	}
	e.redunBuilders = e.redunBuilders[:0]
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
	rquic.SeedFieldMaxSizeUpdate(int(e.redunBuilders[0].builder.SeedMaxFieldSize()))
}

func (e *encoder) redunBuildersNew() *redunBuilder {
	var bfs []*packetBuffer
	var bf *packetBuffer
	var packets [][]byte
	for i := 0; i < e.reduns; i++ {
		bf = getPacketBuffer()
		bf.Data = bf.Data[:cap(bf.Data)]
		bfs = append(bfs, bf)
		packets = append(packets, bf.Data)
	}
	return &redunBuilder{
		builder:    schemes.MakeRedunBuilder(e.scheme, packets, e.offset()),
		buffers:    bfs,
		rateScaler: e.overlapF64,
	}
}

func (e *encoder) assemble(rb *redunBuilder) {
	rQPldPos, codLen := rb.builder.Finish()
	if codLen == 0 {
		return
	} // No SRC, no COD, nothing to assemble

	rQHdrPos := e.offset()
	fieldPosId := rQHdrPos + rquic.FieldPosId
	fieldPosGenId := rQHdrPos + rquic.FieldPosGenId
	lastElemRaw := rQPldPos + codLen - 1
	lastElem := 0

	for _, bf := range rb.buffers {
		// Complete header
		bf.Data[0] = e.firstByte
		copy(bf.Data[1:rQHdrPos], e.currentDCID)
		bf.Data[fieldPosId] = e.rQuicId
		bf.Data[fieldPosGenId] = e.rQuicGenId

		// After linear combination, last useful bytes might become 0. Decoder can handle a packet without them.
		for lastElem = lastElemRaw; bf.Data[lastElem] == 0; lastElem-- {}
		bf.Data = bf.Data[:lastElem+1]

		// Add packet to the assembled packet list
		e.newCodedPackets = append(e.newCodedPackets, bf)

		if rLogger.IsDebugging() {
			rCPos := rQHdrPos + rquic.CodPreHeaderSize
			rLogger.Printf("Encoder Packet pkt.Len:%d DCID.Len:%d hdr(hex):[% X  % X  % X  % X]",
				len(bf.Data), e.lenDCID,
				bf.Data[:rQHdrPos],
				bf.Data[rQHdrPos:rCPos],
				bf.Data[rCPos:rQPldPos],
				bf.Data[rQPldPos:rQPldPos+rquic.CodedOverhead],
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

func (e *encoder) maybeReduceCodingRatio() bool /* did reduce ratio */ {
	cwnd := e.getCongestionWindow()

	curRatio := e.ratio.Check()
	newRatio := float64(cwnd)/protocol.MaxPacketSizeIPv4
	if rquic.LimRateToDecBuffer { // extremely aggressive!
		// Match BTO --> CWND/MaxPktSz packets * 1/sRTT pacing * BTO
		bto := bufferTimeoutDuration(e.localMaxAckDelay)
		rtt := e.smoothedRTT()
		if btoCorrection := float64(bto) / float64(rtt); btoCorrection < 1 {
			newRatio *= btoCorrection
		}
	}

	if newRatio >= curRatio {
		return false
	}

	rLogger.Logf("Encoder Ratio NewRatio(CWND):%f CurrentRatio:%f", newRatio, curRatio)
	e.ratio.Change(newRatio)
	return true
}

func (e *encoder) retrieveCodedPackets() []*packetBuffer {
	if e.encodingPaused {
		return []*packetBuffer{}
	}

	if cods := len(e.newCodedPackets); cods > 0 {
		rLogger.MaybeIncreaseTxCodN(cods)
	}

	defer func() { e.newCodedPackets = []*packetBuffer{} }()
	return e.newCodedPackets
}

// disableCoding stops generating coded packets,
// but does not disable rQUIC
func (e *encoder) disableCoding() {
	e.redunBuildersPurge()
	e.ratioWasDynamic = e.ratio.IsDynamic()
	e.ratio.MakeStatic()
}

func (e *encoder) enableCoding() {
	e.redunBuildersInit()
	if e.ratioWasDynamic {
		e.ratio.MakeDynamic()
	}
}

func (e *encoder) ackStatsUpdate(lost, delivered, unAcked int) {
	e.ratio.AckStatsUpdate(lost, delivered, unAcked)
}

func MakeEncoder(conf *rquic.CConf) *encoder {
	rLogger.Logf("Encoder New %+v", conf)
	dynRatio := rencoder.MakeRatio(
		conf.RatioVal,
		conf.Dynamic >= 0, // Dynamic == 0 --> Default --> Dynamic
		conf.TPeriod,
		conf.NumPeriods,
		conf.GammaTarget,
		conf.DeltaRatio,
	)
	enc := &encoder{
		ratio:            dynRatio,
		scheme:           conf.Scheme,
		overlap:          byte(conf.Overlap),
		overlapInt:       conf.Overlap,
		reduns:           conf.Reduns,
		srcForCoding:     make([]byte, protocol.MaxPacketSizeIPv4),
		encodingPaused:   true, // encodingNotPaused will do the necessary initializations
		localMaxAckDelay: protocol.DefaultMaxAckDelay,
	}
	rLogger.TraceHeader("CWND(B)", "CodeRatio") // Headers of what we want to trace.
	rLogger.Debugf("Encoder Encoding Paused:%+v", enc.encodingPaused)
	return enc
}
