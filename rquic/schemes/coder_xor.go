package schemes

import (
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type redunBuilderXor struct {
	genSize        uint8
	posRQuicHdr    int
	posPld         int
	codedPkts      [][]byte // only 1 pkt per gen
	codedPldLen    int
	codedPldLenMax int
	redun          int
	finished       bool
}

func (r *redunBuilderXor) AddSrc(src []byte) {
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

	// Add SRC
	cod := r.codedPkts[0][r.posPld:]
	var i int
	endLoop := utils.Min(srcLen, r.codedPldLen)
	for ; i < endLoop; i++ {
		cod[i] ^= src[i]
	}
	if endLoop == srcLen {
		return
	}
	for ; i < srcLen; i++ {
		cod[i] = src[i]
	}

	r.codedPldLen = srcLen
}

func (r *redunBuilderXor) ReadyToSend(ratio float64) bool {
	return r.finished || float64(r.genSize+1)/float64(r.redun) > ratio
}

func (r *redunBuilderXor) Finish() (int, int) {
	r.codedPkts[0][r.posRQuicHdr+rquic.FieldPosGenSize] = r.genSize
	r.codedPkts[0][r.posRQuicHdr+rquic.FieldPosType] = rquic.SchemeXor
	for i := 1; i < r.redun; i++ {
		copy(r.codedPkts[i], r.codedPkts[0])
	}
	r.finished = true
	return r.posPld, r.codedPldLen
}

func (r *redunBuilderXor) SeedMaxFieldSize() uint8 { return 0 }

func makeRedunBuilderXor(packets [][]byte, posRQuicHdr int) *redunBuilderXor {
	rb := redunBuilderXor{
		posRQuicHdr: posRQuicHdr,
		posPld:      posRQuicHdr + rquic.CodPreHeaderSize,
		codedPkts:   packets,
		redun:       len(packets),
	}
	rb.codedPldLenMax = len(rb.codedPkts[0]) - rb.posPld
	return &rb
}

func UnpackXor(raw []byte, offset int) ([]byte, int) {
	genSize := raw[offset+rquic.FieldPosGenSize]
	coeffs := make([]uint8, genSize)
	for i := range coeffs {
		coeffs[i] = uint8(1)
	}
	return coeffs, 0
}
