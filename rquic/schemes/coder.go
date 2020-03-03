package schemes

import (
	"github.com/lucas-clemente/quic-go/rquic"
)

func MakeRedunBuilder(scheme uint8, reduns int) RedunBuilder {
	switch scheme {
	case rquic.SchemeXor:
		return makeRedunBuilderXor() // always 1 redun
	case rquic.SchemeRlcSys:
		return makeRedunBuilderRlcSys(reduns)
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
