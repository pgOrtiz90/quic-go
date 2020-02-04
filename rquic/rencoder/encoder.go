package rencoder

import (
    "time"
    
    "github.com/lucas-clemente/quic-go/rquic"
    "github.com/lucas-clemente/quic-go/rquic/schemes"
)



type Encoder struct {
    
    rQuicId             uint8
    
    // DCID                *[]byte
    lenDCID             *int // length of DCID
    
    Ratio               *ratio
    
    Scheme              uint8
    Overlap             uint8                  // overlapping generations, i.e. convolutional
    redunBuilders       []schemes.RedunBuilder // need slice for overlapping/convolutional
}



func (e *Encoder) lenNotProtected() int { return *e.lenDCID + rquic.SrcHeaderSize }
func (e *Encoder) rQuicHdrPos()     int { return 1 /*1st byte*/ + *e.lenDCID }
func (e *Encoder) rQuicSrcPldPos()  int { return 1 /*1st byte*/ + *e.lenDCID + rquic.SrcHeaderSize }



func (e *Encoder) Process(raw []byte, ackEliciting bool) {
    
    // Add rQUIC header to SRC
    if !ackEliciting {
        raw = append(append(raw[:e.rQuicHdrPos()], 0), raw[e.rQuicHdrPos():]...)
        return
    }
    rQuicHdr := []byte{rquic.MaskType, e.rQuicId}
    raw = append(append(raw[:e.rQuicHdrPos()], rQuicHdr...), raw[e.rQuicHdrPos():]...)
    // TODO: Consider inserting rQUIC hdr & TYPE value at QUIC pkt marshalling
    
    // Parse SRC and add it to generations under construction
    rQuicHdr = raw[:e.rQuicSrcPldPos()] // we try to send COD before ACK, spin bit should be ok
    src := e.parseSrc(raw)
    var newCodedPkts [][]byte
    reduns := 1 // Change reduns or genSize? To be researched...
    for ind, rb := range e.redunBuilders {
        rb.AddSrc(src)
        if rb.ReadyToSend(e.Ratio.Check()) {
            // multiple gen-s finished at the same time ---> append
            newCodedPkts = append(newCodedPkts, rb.Assemble(rQuicHdr)...)
            e.redunBuilders[ind] = schemes.MakeRedunBuilder(e.Scheme, reduns)
        }
    }
    // TODO: Find to whom pass newCodedPkts
    
    e.rQuicId++
}

func (e *Encoder) parseSrc(raw []byte) []byte {
    // TODO: same parseSrc as decoder, consider merging
    lng := len(raw) - e.lenNotProtected()
    pldHdr := make([]byte, 3)
    pldHdr[0] = byte(lng / 256)
    pldHdr[1] = byte(lng % 256)
    pldHdr[2] = raw[0] // 1st byte, which is partially encrypted
    return append(pldHdr, raw[e.rQuicSrcPldPos():]...)
}

func (e *Encoder) DisableCoding() {
    e.Ratio.Change(0)
}

func (e *Encoder) AddRetransmissionCount() {
    if e.Ratio.dynamic {
        e.Ratio.AddReTxCount()
    }
}

func (e *Encoder) AddTransmissionCount() {
    if e.Ratio.dynamic {
        e.Ratio.AddTxCount()
    }
}



func MakeEncoder(
    scheme          uint8,
    overlap         uint8,
    dynamic         bool,
    Tperiod         time.Duration,
    numPeriods      int,
    gammaTarget     float64,
    deltaRatio      float64,
) *Encoder {
    
    overlap = 1 // TODO: make overlap work (& with adaptive rate)
    
    enc := &Encoder{
        // lenDCID:             // TODO: Find where to get DCID & its length
        Ratio:          makeRatio(dynamic, Tperiod, numPeriods, gammaTarget, deltaRatio),
        Scheme:         scheme,
        Overlap:        overlap,
        redunBuilders:  make([]schemes.RedunBuilder, overlap),
    }
    
    for i := range enc.redunBuilders {
        enc.redunBuilders[i] = schemes.MakeRedunBuilder(scheme, 1)
    }
    
    return enc
}
