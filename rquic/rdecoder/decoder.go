package rdecoder

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/schemes"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type Decoder struct {
	pktsSrc []*parsedSrc
	pktsCod []*parsedCod

	lenDCID int // length of DCID

	lastScheme uint8
	coeff      schemes.CoeffUnpacker
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

	srcAvbl           []uint8 // used for building srcMiss (missing SRC)
	srcMiss           []uint8 // used for Decoder.Recover()
	doCheckMissingSrc bool    // flag for updating the list of srcMiss

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
		d.logPkt("UNKNOWN", raw, rHdrPos+rquic.CodHeaderSizeMax)
		return rquic.TypeUnknown, d.didRecover
	}

	// protected & coded have pkt.id & gen.id
	p := raw[rHdrPos+rquic.FieldPosId]    // last pkt id
	g := raw[rHdrPos+rquic.FieldPosGenId] // last gen id
	seenNew := d.lastSeen(p, g)
	if d.isObsolete(p, g) {
		d.logPkt("OBSOLETE", raw, rHdrPos+rquic.SrcHeaderSize)
		return rquic.TypeUnknown, d.didRecover
	}
	d.maybeUpdateXhold()

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
	d.doCheckMissingSrc = seenNew
	d.NewCod(raw)
	d.Recover()
	return rquic.TypeCoded, d.didRecover
}

func (d *Decoder) NewSrc(raw []byte) *parsedSrc {
	rHdrPos := d.offset()
	srcPldPos := rHdrPos + rquic.SrcHeaderSize

	pktId := raw[rHdrPos+rquic.FieldPosId]
	if d.srcAvblUpdate(pktId) /* SRC is repeated */ {
		d.logPkt("PROTECTED REPEATED", raw, srcPldPos)
		return nil
	}
	d.logPkt("PROTECTED", raw, srcPldPos)

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

	return ps
}

func (d *Decoder) NewSrcRec(cod *parsedCod) *parsedSrc {
	// Recovered too late or already received in a retransmission? Discard.
	if obsolete, duplicate := d.isObsoletePktId(cod.srcIds[0]), d.srcAvblUpdate(cod.srcIds[0]); obsolete || duplicate {
		rLogger.Debugf("Decoder Packet Recovered DISCARDED pkt.ID:%d Obsolete:%t Duplicate:%t",
			cod.srcIds[0], obsolete, duplicate,
		)
		cod.markAsObsolete()
		return nil
	}
	// cod.pld must be fully decoded. If not, discard.
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
		rLogger.Printf("Decoder Packet RECOVERED pkt.Len:%d DCID.Len:%d hdr(hex):[% X]",
			srcPldPos+len(ps.pld), d.lenDCID, ps.pld[:srcPldPos],
		)
	}

	return ps
}

func (d *Decoder) NewCod(raw []byte) {
	rHdrPos := d.offset()

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

	// Update scheme
	// The use of different schemes at a time is very unlikely.
	newScheme := raw[rHdrPos+rquic.FieldPosType]
	if d.lastScheme != newScheme {
		d.coeff = schemes.MakeCoeffUnpacker(newScheme)
		d.lastScheme = newScheme
	}
	// Get the coefficients
	pc.coeff = d.coeff.Unpack(raw, rHdrPos)

	// Store coded payload
	coeffsInHdr := d.coeff.CoeffFieldSize() // Coefficients in rQUIC header
	if coeffsInHdr < 0 {
		coeffsInHdr = (0 - coeffsInHdr) * pc.remaining
	}
	pldPos := rHdrPos + rquic.FieldPosSeed + coeffsInHdr
	d.logPkt("CODED", raw, pldPos)
	// The next line is necessary for Rx buffer correctly rescuing decoded pld
	raw[rHdrPos+rquic.FieldPosGenSize] = uint8(coeffsInHdr)
	pc.pld = raw[pldPos:protocol.MaxReceivePacketSize] // CODs are not coalesced. Original COD could have been bigger.
	for i := len(raw) - pldPos; i < len(pc.pld); i++ {
		// These values need to be 0.
		// sync.Pool (getPacketBuffer) does not set values to allocated memory.
		pc.pld[i] = 0
	}
	pc.codedOvh = pc.pld[:rquic.LenOfSrcLen+1]
	pc.codedPld = pc.pld[rquic.LenOfSrcLen+1:]
	*pc.fwd = rquic.FlagCoded

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
	return &Decoder{ // if d.pollutionCount < 0 --> Close this path/connection
		pktsSrc: make([]*parsedSrc, 0, rquic.AgeDiff),
		pktsCod: make([]*parsedCod, 0, rquic.AgeDiff),
		srcAvbl: make([]byte, 0, rquic.AgeDiff),
		srcMiss: make([]byte, 0, rquic.AgeDiff),
		distToLastValidId: rquic.AgeDiff - 1,
		// TODO: implement pollution attack detection
		// if COD --> d.pollutionCount -= rquic.MinRate
		// if SRC --> d.pollutionCount++
		pollutionCount: rquic.MinRatio * rquic.RxRedunMarg,
	}
}
