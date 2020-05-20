package schemes

import (
	"github.com/lucas-clemente/quic-go/rquic"
)

func MakeRedunBuilder(scheme uint8, packets [][]byte, posRQuicHdr int) RedunBuilder {
	switch scheme {
	case rquic.SchemeXor:
		return makeRedunBuilderXor(packets, posRQuicHdr)
	case rquic.SchemeRlcSys:
		return makeRedunBuilderRlcSys(packets, posRQuicHdr)
	default:
		return nil
	}
}

func MakeCoeffUnpacker(scheme uint8) CoeffUnpacker {
	switch scheme {
	case rquic.SchemeXor:
		return makeCoeffUnpackerXor()
	case rquic.SchemeRlcSys:
		return makeCoeffUnpackerRlcSys()
	default:
		return nil
	}
}
