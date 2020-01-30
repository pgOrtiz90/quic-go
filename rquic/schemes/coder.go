package schemes

import (
    "github.com/lucas-clemente/quic-go/rquic"
)


func MakeRedunBuilder (scheme uint8, reduns int) *RedunBuilder {
    if redun > rquic.MaxRedun {
    switch scheme {
    case rquic.SchemeXor:
        return makeRedunBuilderXor() // always 1 redun
    case rquic.SchemeSysRlc:
        return makeRedunBuilderSysRlc(reduns)
    default:
        return nil
    }
}


func MakeCoeffUnpacker (scheme uint8) *CoeffUnpacker {
    switch scheme {
    case rquic.SchemeXor:
        return makeCoeffUnpackerXor()
    case rquic.SchemeSysRlc:
        return makeCoeffUnpackerSysRlc()
    default:
        return nil
    }
}

