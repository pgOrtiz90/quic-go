package quic

import (
	"time"
	"bytes"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/schemes"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic/rencoder"
)

type Encoder struct {
	rQuicId       uint8
	lenDCID       int
	prevDCID      []byte
	Ratio         rencoder.DynRatio
	Scheme        uint8
	Overlap       uint8                  // overlapping generations, i.e. convolutional
	redunBuilders []schemes.RedunBuilder // need slice for overlapping/convolutional
}

func (e *Encoder) lenNotProtected() int { return e.lenDCID + rquic.SrcHeaderSize }
func (e *Encoder) rQuicHdrPos() int     { return 1 /*1st byte*/ + e.lenDCID }
func (e *Encoder) rQuicSrcPldPos() int  { return 1 /*1st byte*/ + e.lenDCID + rquic.SrcHeaderSize }

func (e *Encoder) Process(raw []byte, ackEliciting bool, latestDCIDLen int) (newCodedPkts [][]byte) {
	e.lenDCID = latestDCIDLen
	e.AddTransmissionCount()

	// Check if DCID has changed
	newDCID := raw[1 : 1+e.lenDCID]
	doNotResetReduns := true
	if e.prevDCID != nil {
		if !bytes.Equal(e.prevDCID, newDCID) {
			e.prevDCID = newDCID
			doNotResetReduns = false
		}
	} else {
		e.prevDCID = newDCID
	}

	// Add rQUIC header to SRC
	if !ackEliciting { // Not protected
		raw = append(append(raw[:e.rQuicHdrPos()], 0), raw[e.rQuicHdrPos():]...)
		return
	}
	rQuicHdr := []byte{rquic.MaskType, e.rQuicId}
	raw = append(append(raw[:e.rQuicHdrPos()], rQuicHdr...), raw[e.rQuicHdrPos():]...)
	// TODO: Consider inserting rQUIC hdr & TYPE value at QUIC pkt marshalling

	// Parse SRC and add it to generations under construction
	rQuicHdr = raw[:e.rQuicSrcPldPos()] // we try to send COD before ACK, spin bit should be ok
	src := e.parseSrc(raw)
	reduns := 1 // Change reduns or genSize? To be researched...
	if doNotResetReduns {
		for ind, rb := range e.redunBuilders {
			rb.AddSrc(src)
			if rb.ReadyToSend(e.Ratio.Check()) {
				// multiple gen-s finished at the same time ---> append
				newCodedPkts = append(newCodedPkts, rb.Assemble(rQuicHdr)...)
				e.redunBuilders[ind] = schemes.MakeRedunBuilder(e.Scheme, reduns)
				// TODO: Consider using sync.Pool for coded packets (buffer_pool.go)
			}
		}
		e.rQuicId++
		return
	}

	// if DCID changed, reset redunBuilders
	for i, rb := range e.redunBuilders {
		newCodedPkts = append(newCodedPkts, rb.Assemble(rQuicHdr)...)
		e.redunBuilders[i] = schemes.MakeRedunBuilder(rb.Scheme(), rb.Reduns())
	}
	e.rQuicId++ // TODO: consider adding a random number
	return
}

func (e *Encoder) parseSrc(raw []byte) []byte {
	lng := len(raw) - e.lenNotProtected()
	// 1st byte, which is partially encrypted .....______
	return append(append(rquic.PldLenPrepare(lng), raw[0]), raw[e.rQuicSrcPldPos():]...)
	// TODO: manage memory (too much appending)
}

// updateRQuicOverhead has to be called whenever a coding scheme is changed
func (e *Encoder) updateRQuicOverhead() {
	var sizeSeedCoeff int
	for _, rb := range e.redunBuilders {
		sizeSeedCoeff = utils.Max(sizeSeedCoeff, int(rb.SeedMaxFieldSize()))
	}
	rquic.SeedFieldMaxSizeUpdate(sizeSeedCoeff)
}

func (e *Encoder) MaybeReduceCodingRatio(minPktsCwnd protocol.ByteCount) bool /* did reduce ratio */ {
	newRatio := float64(minPktsCwnd)
	if newRatio < e.Ratio.Check() {
		e.Ratio.Change(newRatio)
		return true
	}
	return false
}

func (e *Encoder) DisableCoding() {
	e.Ratio.Change(0)
}

func (e *Encoder) UpdateUnAcked(loss, unAcked int) {
	e.Ratio.UpdateUnAcked(loss, unAcked)
}

func (e *Encoder) AddTransmissionCount() {
	e.Ratio.AddTxCount()
}

func MakeEncoder(
	scheme uint8,
	overlap uint8,
	dynamic bool,
	Tperiod time.Duration,
	numPeriods int,
	gammaTarget float64,
	deltaRatio float64,
) *Encoder {

	overlap = 1 // TODO: make overlap work (& with adaptive rate)

	enc := &Encoder{
		Ratio:         rencoder.MakeRatio(dynamic, Tperiod, numPeriods, gammaTarget, deltaRatio),
		Scheme:        scheme,
		Overlap:       overlap,
		redunBuilders: make([]schemes.RedunBuilder, overlap),
	}

	for i := range enc.redunBuilders {
		enc.redunBuilders[i] = schemes.MakeRedunBuilder(scheme, 1)
	}
	rquic.SeedFieldMaxSizeUpdate(int(enc.redunBuilders[0].SeedMaxFieldSize()))

	return enc
}
