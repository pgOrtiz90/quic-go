package schemes



type RedunBuilder interface {
    //updateCoeffs()
    AddSrc([]byte)
    ReadyToSend(float64)    bool        // takes ratio as input
    Assemble([]byte)        [][]byte    // Takes rQUIC SRC header, expands it and adds coded payload
    SeedFieldSize()         int
}



type CoeffUnpacker interface {
    Unpack(raw *[]byte) []uint8
    CoeffFieldSize() int // negative outputs are genSize multipliers
}

