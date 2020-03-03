package schemes

import (
	"math/rand"

	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/gf"
)

//////////////////////////////////////////////////////////////////////// redunBuilder

type redunBuilderRlcSys struct {
	scheme      uint8
	genSize     uint8
	coeffs      [][]uint8
	payloads    [][]byte
	codedPktLen int
	redun       int // coded packets in this gen
}

func newCoeff() uint8 {
	// rand.Seed(time.Now().UnixNano()) // Gogoratuzu!
	return uint8(rand.Intn(rquic.MaxGf-1) + 1)
}

func (r *redunBuilderRlcSys) AddSrc(src []byte) {
	var cf uint8
	difLen := len(src) - r.codedPktLen
	if difLen > 0 {
		r.codedPktLen = len(src)
	}

	for i := 0; i < r.redun; i++ {
		// Update coded payloads' lengths
		if difLen > 0 {
			r.payloads[i] = append(r.payloads[i], make([]byte, difLen)...)
		}
		// Update coefficients
		cf = newCoeff()
		r.coeffs[i] = append(r.coeffs[i], cf)
		// Add SRC
		for j, v := range src {
			r.payloads[i][j] ^= gf.Mult(v, cf)
		}
	}
	r.genSize++
}

func (r *redunBuilderRlcSys) ReadyToSend(ratio float64) bool {
	if r.genSize >= rquic.MaxGenSize {
		return true
	}
	return float64(r.genSize)/float64(r.redun) > ratio
}

func (r *redunBuilderRlcSys) Assemble(rQuicSrcHdr []byte) [][]byte {
	for i, pld := range r.payloads {
		r.payloads[i] = append(append(append(rQuicSrcHdr, r.genSize), r.coeffs[i]...), pld...)
	}
	return r.payloads
}

func (r *redunBuilderRlcSys) SeedMaxFieldSize() uint8 { // TODO: limit SRC payload length
	return rquic.MaxGenSize
}

func (r *redunBuilderRlcSys) Scheme() byte {
	return r.scheme
}

func (r *redunBuilderRlcSys) Reduns() int {
	return r.redun
}

func makeRedunBuilderRlcSys(reduns int) *redunBuilderRlcSys {
	return &redunBuilderRlcSys{
		scheme:   rquic.SchemeRlcSys,
		coeffs:   make([][]uint8, reduns),
		payloads: make([][]uint8, reduns),
		redun:    reduns,
	}
}

//////////////////////////////////////////////////////////////////////// coeffUnpacker

type coeffUnpackerRlcSys struct{}

func (c *coeffUnpackerRlcSys) Unpack(raw []byte, offset int) (coeffs []uint8) {
	genSize := int(raw[offset+rquic.FieldPosGenSize])
	coeffs = make([]uint8, genSize)
	cffsStart := offset + rquic.FieldPosSeed
	copy(coeffs, raw[cffsStart:cffsStart+genSize])
	return
}

func (c *coeffUnpackerRlcSys) CoeffFieldSize() int {
	return -1 // 1 * genSize
}

func makeCoeffUnpackerRlcSys() *coeffUnpackerRlcSys {
	return &coeffUnpackerRlcSys{}
}
