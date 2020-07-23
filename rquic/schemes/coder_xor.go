package schemes

import (
	"github.com/lucas-clemente/quic-go/rquic"
)

//////////////////////////////////////////////////////////////////////// redunBuilder

type redunBuilderXor struct {
	scheme      uint8
	genSize     uint8
	posRQuicHdr int
	codedPkt    []byte // only 1 pkt per gen
	codedPldLen int
	finished    bool
}

func (r *redunBuilderXor) AddSrc(src []byte) {
	if r.finished {
		return
	}
	if len(src) > r.codedPldLen {
		return
	} // Packets that are filled here are max size

	// Add SRC
	for i, v := range src {
		r.codedPkt[i] ^= v
	}
	r.genSize++
}

func (r *redunBuilderXor) ReadyToSend(ratio float64) bool {
	if r.genSize >= rquic.MaxGenSize {
		return true
	}
	return float64(r.genSize) > ratio
}

func (r *redunBuilderXor) Finish() {
	r.codedPkt[0] = 0
	r.codedPkt[r.posRQuicHdr+rquic.FieldPosGenSize] = r.genSize
	r.codedPkt[r.posRQuicHdr+rquic.FieldPosType] = r.scheme
	r.finished = true
}

func (r *redunBuilderXor) SeedMaxFieldSize() uint8 {
	return 0
}

func (r *redunBuilderXor) Scheme() byte {
	return r.scheme
}

func (r *redunBuilderXor) Reduns() int {
	return 1
}

func makeRedunBuilderXor(packets [][]byte, posRQuicHdr int) *redunBuilderXor {
	rb := redunBuilderXor{
		scheme:      rquic.SchemeXor,
		posRQuicHdr: posRQuicHdr,
		codedPkt:    packets[0],
		codedPldLen: len(packets[0]) - (posRQuicHdr + rquic.FieldPosSeed),
	}
	return &rb
}

//////////////////////////////////////////////////////////////////////// coeffUnpacker

type coeffUnpackerXor struct{}

func (c *coeffUnpackerXor) Unpack(raw []byte, offset int) (coeffs []uint8) {
	genSize := raw[offset+rquic.FieldPosGenSize]
	coeffs = make([]uint8, genSize)
	for i := range coeffs {
		coeffs[i] = uint8(1)
	}
	return
}

func (c *coeffUnpackerXor) CoeffFieldSize() int {
	return 0
}

func makeCoeffUnpackerXor() *coeffUnpackerXor {
	return &coeffUnpackerXor{}
}
