package rdecoder

import (
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/schemes"
)

type Decoder struct {
	pktsSrc []*parsedSrc
	pktsCod []*parsedCod

	lenDCID int // length of DCID

	lastScheme uint8
	coeff      schemes.CoeffUnpacker

	// Obsolete packets detection
	nwstCodId     uint8
	obsoleteXhold uint8

	srcAvbl           []uint8 // used for building srcMiss (missing SRC)
	srcMiss           []uint8 // used for Decoder.Recover()
	doCheckMissingSrc bool    // flag for updating the list of srcMiss

	pollutionCount float64
}

func (d *Decoder) Process(raw []byte) bool {

	rHdrPos := d.rQuicHdrPos()
	ptype := raw[rHdrPos+rquic.FieldPosTypeScheme]

	// unprotected packet
	if ptype == 0 {
		raw = append(raw[:rHdrPos], raw[rHdrPos+1:]...)
		return true // forward this packet to QUIC
	}

	// protected packet
	if ptype&rquic.MaskType == 0 {
		if src := d.NewSrc(raw); src != nil {
			d.optimizeWithSrc(src)
			return true
		}
		return false
	}

	// coded packet
	if ptype&rquic.MaskType != 0 {
		d.NewCod(raw)
		d.Recover()
	}

	// Coded and unknown packets are discarded
	return false // do not forward this packet to QUIC
}

func (d *Decoder) NewSrc(raw []byte) (ps *parsedSrc) {
	rHdrPos := d.rQuicHdrPos()

	id := raw[rHdrPos+rquic.FieldPosId]
	if d.isObsolete(id) {
		return
	} // if SRC is TOO OLD
	if d.srcAvblUpdate(id) {
		return
	} // or REPEATED, discard it

	// Parse & store SRC
	ps = &parsedSrc{
		id:  id,
		pld: d.parseSrc(raw),
	}
	d.pktsSrc = append(d.pktsSrc, ps)

	// Remove rQUIC header and leave raw packet ready for QUIC
	raw = append(raw[:rHdrPos], raw[d.rQuicSrcPldPos():]...)

	return
}

func (d *Decoder) NewSrcRec(cod *parsedCod) (ps *parsedSrc) { // cod.pld must be fully decoded

	lastPos := int(cod.pld[0])*256 + int(cod.pld[1]) /*length*/ - 1 /*1st byte*/ + 3 /*pld offset*/

	raw := append(append([]byte{cod.pld[2]}, cod.quicDCID...), cod.pld[3:lastPos]...)
	// TODO: Find to whom pass this new SRC & report it as RECOVERED

	// New SRC
	if d.isObsolete(cod.srcIds[0]) {
		return
	} // if SRC is TOO OLD
	if d.srcAvblUpdate(cod.srcIds[0]) {
		return
	} //  or REPEATED, discard it
	ps = &parsedSrc{
		id:  cod.srcIds[0],
		pld: cod.pld[:lastPos],
	}
	d.pktsSrc = append(d.pktsSrc, ps)
	return
}

func (d *Decoder) NewCod(raw []byte) {
	rHdrPos := d.rQuicHdrPos()

	pc := &parsedCod{
		remaining: int(raw[rHdrPos+rquic.FieldPosGenSize]),
		quicDCID:  raw[1 : 1+d.lenDCID], // CODED could be used after Tx changes DCID
	} // till pc is optimized at the end of this method, remaining == genSize

	// Update scheme
	// The use of different schemes at a time is very unlikely.
	newScheme := raw[rHdrPos+rquic.FieldPosTypeScheme] & rquic.MaskScheme
	if d.lastScheme != newScheme {
		d.coeff = schemes.MakeCoeffUnpacker(newScheme)
		d.lastScheme = newScheme
	}

	// Get the coefficients
	pc.coeff = d.coeff.Unpack(raw, rHdrPos)
	if d.isObsolete(pc.coeff[0]) {
		return
	}

	// List of SRC IDs covered by this COD
	pc.srcIds = make([]uint8, pc.remaining)
	pcId := raw[rHdrPos+rquic.FieldPosId]
	pc.srcIds[0] = pcId - uint8(pc.remaining) + 1
	for i := 1; i < pc.remaining; i++ {
		pc.srcIds[i] = pc.srcIds[i-1] + 1
	}

	// Store coded payload
	totalOverh := d.coeff.CoeffFieldSize()
	if totalOverh < 0 {
		totalOverh = (0 - totalOverh) * pc.remaining
	}
	totalOverh = rHdrPos + rquic.FieldPosSeed + totalOverh /*coefficients*/
	pc.pld = make([]byte, len(raw)-totalOverh)
	copy(pc.pld, raw[totalOverh:])

	// Update obsolete packets detection threshold
	if idLolderR(d.nwstCodId, pcId) {
		d.updateObsoleteXhold(pc)
	}

	// Remove existing SRC from this new COD
	if srcs, inds, genNotFull := d.optimizeThisCodAim(pc); genNotFull {
		if d.optimizeThisCodFire(pc, srcs, inds) { // COD is useful
			d.pktsCod = append(d.pktsCod, pc) // Store new parsed COD
		}
	}
}

func MakeDecoder() *Decoder {
	return &Decoder{
		// DCID:               // TODO: Find where to get DCID & its length
		// lenDCID:

		pollutionCount: rquic.MinRatio * rquic.RxRedunMarg,
		// TODO: implement pollution attack detection
		// if SRC --> d.pollutionCount++
		// if COD --> d.pollutionCount -= rquic.MinRate
		// if d.pollutionCount < 0 --> Close this path/connection
	}
}
