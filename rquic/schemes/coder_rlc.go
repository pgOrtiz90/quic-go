package schemes

import (
	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"github.com/lucas-clemente/quic-go/rquic/gf"
)

type redunBuilderRlcSys struct {
	genSize        uint8
	posGenSize     int
	posScheme      int
	posCoeffs      int
	posNewCoeff    int
	posPld         int
	codedPkts      [][]byte
	codedPldLen    int
	codedPldLenMax int
	redun          int // coded packets in this gen
	finished       bool
}

func newCoeff() uint8 {
	// rand.Seed(time.Now().UnixNano())
	return uint8(rand.Intn(rquic.MaxGf-1) + 1)
}

func (r *redunBuilderRlcSys) AddSrc(src []byte) {
	if r.finished {
		return
	}
	srcLen := len(src)
	if srcLen > r.codedPldLenMax {
		rLogger.Logf("Encoder ERROR SrcPldLen:%d > CodPldLen:%d", srcLen, r.codedPldLenMax)
		return
	} // Packets that are filled here are max size

	r.genSize++
	r.finished = r.genSize == rquic.GenSizeMax

	var cf uint8
	var i int
	endLoop := utils.Min(srcLen, r.codedPldLen)
	for _, cod := range r.codedPkts {

		// Update coefficients
		cf = newCoeff()
		cod[r.posNewCoeff] = cf

		// Write header if this is the last packet in gen.
		if r.finished {
			cod[r.posGenSize] = r.genSize
			cod[r.posScheme] = rquic.SchemeRlcSys
		}

		// Add SRC
		cod = cod[r.posPld:]
		for i = 0 ; i < endLoop; i++ {
			cod[i] ^= gf.Mult(src[i], cf)
		}
		if endLoop == srcLen {
			continue
		}
		for ; i < srcLen; i++ {
			cod[i] = gf.Mult(src[i], cf)
		}
	}
	r.codedPldLen = srcLen
	r.posNewCoeff++
}

func (r *redunBuilderRlcSys) ReadyToSend(ratio float64) bool {
	return r.finished || float64(r.genSize+1)/float64(r.redun) > ratio
}

func (r *redunBuilderRlcSys) Finish() (int, int) {
	if r.finished {
		return r.posNewCoeff, r.codedPldLen
	}

	for _, cod := range r.codedPkts {
		cod[r.posGenSize] = r.genSize
		cod[r.posScheme] = rquic.SchemeRlcSys
		if r.finished { // r.posNewCoeff == r.posPld
			continue
		}
		copy(cod[r.posNewCoeff:], cod[r.posPld:])
	}

	r.finished = true
	return r.posNewCoeff, r.codedPldLen
}

func (r *redunBuilderRlcSys) SeedMaxFieldSize() uint8 { return rquic.GenSizeMax }

func makeRedunBuilderRlcSys(packets [][]byte, posRQuicHdr int) *redunBuilderRlcSys {
	redun := len(packets)
	if redun == 0 {
		return nil
	}
	posCoeffs := posRQuicHdr + rquic.FieldPosSeed
	posPld := posCoeffs + int(rquic.GenSizeMax)
	return &redunBuilderRlcSys{
		posGenSize:     posRQuicHdr + rquic.FieldPosGenSize,
		posScheme:      posRQuicHdr + rquic.FieldPosType,
		posCoeffs:      posCoeffs,
		posNewCoeff:    posCoeffs,
		posPld:         posPld,
		codedPkts:      packets,
		codedPldLenMax: len(packets[0]) - posPld,
		redun:          redun,
	}
}

func UnpackRlcSys(raw []byte, offset int) ([]byte, int) {
	genSize := int(raw[offset+rquic.FieldPosGenSize])
	coeffs := make([]uint8, genSize)
	cffsStart := offset + rquic.FieldPosSeed
	copy(coeffs, raw[cffsStart:cffsStart+genSize])
	return coeffs, genSize
}
