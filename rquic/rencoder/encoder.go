package rencoder

import {
    "sync"
    
    "github.com/lucas-clemente/quic-go/rquic"
    "github.com/lucas-clemente/quic-go/rquic/schemes"
}



type encoder struct {
    
    rQuicId             uint8
    
    // DCID                *[]byte
    lenDCID             *int // length of DCID
    
    Ratio               *Ratio
    
    Scheme              uint8
    Overlap             uint8                   // overlapping generations, i.e. convolutional
    redunBuilders       []*schemes.RedunBuilder // need slice for overlapping/convolutional
}



func (e *encoder) lenNotProtected() {return *e.lenDCID + rquic.SrcHeaderSize}
func (e *encoder) rQuicHdrPos()     {return 1 /*1st byte*/ + *e.lenDCID}
func (e *encoder) rQuicSrcPldPos()  {return 1 /*1st byte*/ + *e.lenDCID + rquic.SrcHeaderSize}



func (e *encoder) Process(raw []byte, ackEliciting bool) {
    
    // Add rQUIC header to SRC
    if !ackEliciting {
        raw = append(  append(raw[:e.rQuicHdrPos()], 0)  , raw[e.rQuicHdrPos():]...)
        return
    }
    rQuicHdr := []byte{rquic.MaskType, e.rQuicIds}
    raw = append(  append(raw[:e.rQuicHdrPos()], rQuicHdr...)  , raw[e.rQuicHdrPos():]...)
    // TODO: Consider inserting rQUIC hdr & TYPE value at QUIC pkt marshalling
    
    // Parse SRC and add it to generations under construction
    rQuicHdr = raw[:e.rQuicSrcPldPos()] // we try to send COD before ACK, spin bit should be ok
    src := e.parseSrc(raw)
    var newCodedPkts [][]byte
    reduns := 1 // Change reduns or genSize? To be researched...
    for ind, rb := range e.redunBuilders {
        rb.AddSrc(src)
        if rb.Ratio() >= e.Ratio.Check() {
            // multiple gen-s finished at the same time ---> append
            newCodedPkts = append(newCodedPkts, rb.Assemble(rQuicHdr)...)
            e.redunBuilders[ind] = schemes.MakeRedunBuilder(e.Scheme, reduns)
        }
    }
    // TODO: Find to whom pass newCodedPkts
    
    e.rQuicId++
}

func (e *encoder) parseSrc(raw []byte) []byte {
    // TODO: same parseSrc as decoder, consider merging
    lng := len(raw) - e.lenNotProtected()
    pldHdr := make([]byte, 3)
    pldHdr[0] = byte(lng / 256)
    pldHdr[1] = byte(lng % 256)
    pldHdr[2] = raw[0] // 1st byte, which is partially encrypted
    return append(pldHdr, raw[e.rQuicSrcPldPos():]...)
}

func (e *encoder) DisableCoding() {
    e.Ratio.Change(0)
}

func (e *encoder) AddRetransmissionCount {
    if e.Ratio.dynamic {
        e.Ratio.AddReTxCount()
    }
}

func (e *encoder) AddTransmissionCount {
    if e.Ratio.dynamic {
        e.Ratio.AddTxCount()
    }
}



func MakeEncoder(
    scheme          uint8,
    dynamic         bool,
    Tperiod         time.Period,
    numPeriods      int,
    gammaTarget     float64,
    deltaRatio      uint8,
) *encoder {
    
    enc = &encoder {
        // lenDCID:             // TODO: Find where to get DCID & its length
        Ratio:          makeRatio(dynamic, Tperiod, numPeriods, gammaTarget, deltaRatio)
        Scheme:         scheme,
        Overlap:        1, // TODO: make overlap work (& with adaptive rate)
        redunBuilders:  make([])
    }
    
    enc.redunBuilders = make([]*schemes.RedunBuilder, enc.Overlap)
    for i := range enc.redunBuilders {
        enc.redunBuilders[i] = MakeRedunBuilder(scheme, 1)
    }
    
    return enc
}
