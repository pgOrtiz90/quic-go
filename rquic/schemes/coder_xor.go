package schemes

import (
	"github.com/lucas-clemente/quic-go/rquic"
)

//////////////////////////////////////////////////////////////////////// redunBuilder

type redunBuilderXor struct {
	scheme      uint8
	genSize     uint8
	payload     []byte // only 1 pkt per gen
	codedPktLen int
}

func (r *redunBuilderXor) AddSrc(src []byte) {
	// Update coded payloads' lengths
	srcLen := len(src) // int
	if difLen := srcLen - r.codedPktLen; difLen > 0 {
		r.payload = append(r.payload, make([]byte, difLen)...)
		r.codedPktLen = srcLen
	}
	// Add SRC
	for i, v := range src {
		r.payload[i] ^= v
	}
	r.genSize++
}

func (r *redunBuilderXor) ReadyToSend(ratio float64) bool {
	if r.genSize >= rquic.MaxGenSize {
		return true
	}
	return float64(r.genSize) > ratio
}

func (r *redunBuilderXor) Assemble(rQuicSrcHdr []byte) [][]byte {
	r.payload = append(append(rQuicSrcHdr, r.genSize), r.payload...)
	return [][]byte{r.payload}
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

func makeRedunBuilderXor() *redunBuilderXor {
	rb := redunBuilderXor{
		scheme: rquic.SchemeXor,
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
