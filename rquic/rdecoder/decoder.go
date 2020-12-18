package rdecoder

import (
	"fmt"
	"strings"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/schemes"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type Decoder struct {
	pktsSrc []*parsedSrc
	pktsCod []*parsedCod

	lenDCID int // length of DCID

	lastScheme uint8
	unpack     func([]byte, int)([]byte, int)
	didRecover bool

	// Obsolete packets detection
	lastSeenGen           uint8
	lastSeenPkt           uint8
	lastSeenOverlap       uint8
	lastValidGen          uint8
	obsoleteXhold         uint8 // rQUIC ID of the last valid packet
	distToLastValidId     uint8 // used for updating obsoleteXhold
	obsoleteSrcChecked    bool
	obsoleteCodCheckedInd int

	srcMiss     []uint8
	lastSeenSrc uint8

	pollutionCount float64
}

func (d *Decoder) Process(raw []byte, currentSCIDLen int) (uint8, bool) {
	d.lenDCID = currentSCIDLen
	d.didRecover = false
	d.obsoleteSrcChecked = false

	rHdrPos := d.offset()
	ptype := raw[rHdrPos+rquic.FieldPosType]

	// unprotected packet
	if ptype == rquic.TypeUnprotected {
		d.logPkt("UNPROTECTED", raw, rHdrPos+rquic.FieldPosType+rquic.FieldSizeType)
		return rquic.TypeUnprotected, d.didRecover
	}

	// unknown packet
	if ptype >= rquic.TypeUnknown {
		d.logPkt("UNKNOWN   ", raw, rHdrPos+rquic.CodHeaderSizeMax)
		return rquic.TypeUnknown, d.didRecover
	}

	// protected & coded have pkt.id & gen.id
	p := raw[rHdrPos+rquic.FieldPosId]    // last pkt id
	g := raw[rHdrPos+rquic.FieldPosGenId] // last gen id
	d.lastSeen(p, g)
	d.maybeUpdateXhold()
	if d.isObsolete(p, g) {
		d.logPkt("OBSOLETE  ", raw, rHdrPos+rquic.SrcHeaderSize)
		return rquic.TypeUnknown, d.didRecover
	}

	// protected packet
	if ptype == rquic.TypeProtected {
		if src := d.NewSrc(raw); src != nil {
			d.optimizeWithSrc(src, true)
			return rquic.TypeProtected, d.didRecover
		}
		// src == nil --> Could not process SRC, discard it.
		return rquic.TypeUnknown, d.didRecover
	}

	// coded packet
	d.NewCod(raw)
	d.Recover()
	return rquic.TypeCoded, d.didRecover
}

func (d *Decoder) NewSrc(raw []byte) *parsedSrc {
	rHdrPos := d.offset()
	srcPldPos := rHdrPos + rquic.SrcHeaderSize

	pktId := raw[rHdrPos+rquic.FieldPosId]
	if d.alreadyReceived(pktId) {
		d.logPkt("PROTECTED REPEATED", raw, srcPldPos)
		return nil
	}
	d.logPkt("PROTECTED  ", raw, srcPldPos)

	ps := &parsedSrc{
		id:      pktId,
		lastGen: raw[rHdrPos+rquic.FieldPosLastGen],
		overlap: raw[rHdrPos+rquic.FieldPosOverlap],
		fwd:     &raw[rHdrPos+rquic.FieldPosType], // reusing type field
		pld:     raw[srcPldPos:],
	}
	ps.ovh2code = append(rquic.PldLenPrepare(len(ps.pld)), raw[0])
	d.lastSeenOverlap = ps.overlap

	*ps.fwd = rquic.FlagSource
	raw[rHdrPos+rquic.FieldPosGenSize] = 0 // rQUIC field reused for showing number of coefficients in the header
	d.pktsSrc = append(d.pktsSrc, ps)

	rLogger.MaybeIncreaseRxSrc()

	d.maybeCheckObsoleteSrc()

	return ps
}

func (d *Decoder) NewSrcRec(cod *parsedCod) *parsedSrc {
	if d.isObsoletePktId(cod.srcIds[0]) {
		rLogger.Debugf("Decoder Packet Recovered DISCARDED pkt.ID:%d Obsolete", cod.srcIds[0])
		cod.markAsObsolete()
		return nil
	}
	if d.alreadyReceived(cod.srcIds[0]) {
		rLogger.Debugf("Decoder Packet Recovered DISCARDED pkt.ID:%d Duplicate", cod.srcIds[0])
		cod.markAsObsolete()
		return nil
	}
	if cod.remaining > 1 {
		rLogger.Logf("ERROR Decoder RecoveredPkt NotDecoded srcIDs:%d coeffs:%d", cod.srcIds, cod.coeff)
		cod.markAsObsolete()
		return nil
	}
	cod.scaleDown()
	*cod.fwd |= rquic.FlagSource
	*cod.rid = cod.srcIds[0]

	ps := &parsedSrc{
		id: cod.srcIds[0],
		//// These fields are consulted only when brand new packet is received
		// lastSeenGen: cod.genId
		// overlap: 0
		fwd:      cod.fwd,
		pld:      cod.codedPld[:rquic.PldLenRead(cod.codedOvh, 0)],
		ovh2code: cod.codedOvh,
	}
	d.pktsSrc = append(d.pktsSrc, ps)
	d.didRecover = true

	rLogger.MaybeIncreaseRxRec()
	if rLogger.IsDebugging() {
		srcPldPos := d.offset() + rquic.SrcHeaderSize
		reconstructedHeader := strings.Repeat("?? ", 1 + d.lenDCID)
		reconstructedHeader += fmt.Sprintf("% X", []byte{rquic.TypeProtected, ps.id, cod.genId, d.lastSeenOverlap})
		rLogger.Printf("Decoder Packet RECOVERED   pkt.Len:%d DCID.Len:%d hdr(hex):[%s]",
			srcPldPos+len(ps.pld), d.lenDCID,// raw[:srcPldPos], // No access to raw from here
			reconstructedHeader,
		)
	}

	return ps
}

func (d *Decoder) NewCod(raw []byte) {
	rHdrPos := d.offset()
	var coeffSeedSize int

	rLogger.MaybeIncreaseRxCod()

	pc := &parsedCod{
		genSize: raw[rHdrPos+rquic.FieldPosGenSize],
		genId:   raw[rHdrPos+rquic.FieldPosGenId],
		fwd:     &raw[rHdrPos+rquic.FieldPosType], // reusing type field
		rid:     &raw[rHdrPos+rquic.FieldPosId], // necessary for rQuicBuffer
	}
	// till pc is optimized at the end of this method, remaining == genSize
	pc.remaining = int(pc.genSize)

	// List of SRC IDs covered by this COD
	pc.srcIds = make([]uint8, pc.remaining)
	pc.id = raw[rHdrPos+rquic.FieldPosId]
	pc.srcIds[0] = pc.id - uint8(pc.remaining) + 1
	for i := 1; i < pc.remaining; i++ {
		pc.srcIds[i] = pc.srcIds[i-1] + 1
	}

	// Get the coefficients
	newScheme := raw[rHdrPos+rquic.FieldPosType]
	if d.lastScheme != newScheme {
		// The use of different schemes at a time is very unlikely.
		d.unpack = schemes.GetCoeffUnpacker(newScheme)
		d.lastScheme = newScheme
	}
	pc.coeff, coeffSeedSize = d.unpack(raw, rHdrPos)
	raw[rHdrPos+rquic.FieldPosGenSize] = uint8(coeffSeedSize) // for Rx buffer

	// Store coded payload
	pldPos := rHdrPos + rquic.FieldPosSeed + coeffSeedSize
	pc.pld = raw[pldPos:] // CODs are not coalesced. Original COD could have been bigger.
	pc.codedOvh = pc.pld[:rquic.LenOfSrcLen+1]
	pc.codedPld = pc.pld[rquic.LenOfSrcLen+1:]
	*pc.fwd = rquic.FlagCoded
	d.logPkt("CODED      ", raw, pldPos)

	// Remove existing SRC from this new COD
	if srcs, inds, genNotFull := d.optimizeThisCodAim(pc); genNotFull {
		if d.optimizeThisCodFire(pc, srcs, inds) { // COD is useful
			d.pktsCod = append(d.pktsCod, pc) // Store new parsed COD
		}
	}
}

func (d *Decoder) logPkt(pktType string, raw []byte, end int) {
	if !rLogger.IsDebugging() {
		return
	}
	rLogger.Printf("Decoder Packet %s pkt.Len:%d DCID.Len:%d hdr(hex):[% X]",
		pktType, len(raw), d.lenDCID, raw[:end],
	)
}

func MakeDecoder() *Decoder {
	rLogger.Logf("Decoder New")
	rquic.AgeDiffSet()
	d := &Decoder{ // if d.pollutionCount < 0 --> Close this path/connection
		pktsSrc: make([]*parsedSrc, 0, rquic.AgeDiff),
		pktsCod: make([]*parsedCod, 0, rquic.AgeDiff),
		srcMiss: make([]byte, 0, rquic.AgeDiff),
		distToLastValidId: rquic.AgeDiff - 1,
		// TODO: implement pollution attack detection
		// if COD --> d.pollutionCount -= rquic.MinRate
		// if SRC --> d.pollutionCount++
		pollutionCount: rquic.MinRatio * rquic.RxRedunMarg,
	}
	d.lastSeenSrc--
	return d
}
