package schemes



type RedunBuilder interface {
    //updateCoeffs()
    AddSrc([]byte)
    ReadyToSend(float64)    bool        // takes ratio as input
    Assemble([]byte)        [][]byte    // Takes rQUIC SRC header, expands it and adds coded payload
    SeedMaxFieldSize()         uint8
}



type CoeffUnpacker interface {
    Unpack([]byte, int) []uint8
    CoeffFieldSize() int // negative outputs are genSize multipliers
}

