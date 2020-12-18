package schemes

import (
	"fmt"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type RedunBuilder interface {
	AddSrc([]byte)
	ReadyToSend(float64) bool // takes ratio as input
	Finish() (int, int)
	SeedMaxFieldSize() uint8
}

func MakeRedunBuilder(scheme uint8, packets [][]byte, posRQuicHdr int) RedunBuilder {
	switch scheme {
	case rquic.SchemeXor:
		return makeRedunBuilderXor(packets, posRQuicHdr)
	case rquic.SchemeRlcSys:
		return makeRedunBuilderRlcSys(packets, posRQuicHdr)
	default:
		msg := fmt.Sprintf("rQUIC ERROR: unknown coding scheme %d, failed to create an encoder.", scheme)
		rLogger.Logf(msg)
		panic(msg)
	}
}

func GetCoeffUnpacker(scheme uint8) func([]byte, int)([]byte, int) {
	switch scheme {
	case rquic.SchemeXor:
		return UnpackXor
	case rquic.SchemeRlcSys:
		return UnpackRlcSys
	default:
		msg := fmt.Sprintf("rQUIC ERROR: unknown coding scheme %d, failed to unpack coefficients.", scheme)
		rLogger.Logf(msg)
		panic(msg)
	}
}
