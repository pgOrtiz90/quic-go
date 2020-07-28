package schemes

type RedunBuilder interface {
	//updateCoeffs()
	AddSrc([]byte)
	ReadyToSend(float64) bool // takes ratio as input
	Finish() int
	SeedMaxFieldSize() uint8
	Scheme() byte
	Reduns() int
}

type CoeffUnpacker interface {
	Unpack([]byte, int) []uint8
	CoeffFieldSize() int // negative outputs are genSize multipliers
}
