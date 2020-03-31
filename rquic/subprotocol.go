package rquic

////////////////////////////////////////////////////////////////////////// Scheme
const (
	SchemeNoCode uint8 = iota // 0x00
	SchemeXor
	SchemeRlcSys
	//SchemeRlc
	//SchemeRlcSparse
	//SchemeRlcRev
	//SchemeReedSolomon
	//SchemeBch
	//SchemeFulcrum
	//SchemeBats
	// What else?
)

////////////////////////////////////////////////////////////////////////// Type
// of rQUIC packet
const (
	TypeCoded uint8 = iota
	TypeProtected
	TypeUnprotected
	TypeUnknown
)

////////////////////////////////////////////////////////////////////////// Field
// SRC
//    [   1st byte   ]
//    [                 Destination Connection ID                    ]
//    [ type  scheme ][    pkt id    ][ last gen. id ][   overlap    ]
// COD
//    [   1st byte   ]
//    [                 Destination Connection ID                    ]
//    [ type  scheme ][    pkt id    ][    gen id    ][  gen.  size  ]
//    [ seed / coeff   ... ... ... ... ... ... ... ... ... ... ... ...
//    ...  up to MaxGenSize * n (n /*coeff size*/ = /*always(?)*/ 1) ]
const ( //---------------------------------------------------------------- FieldSize
	FieldSizeTypeScheme int = 1
	FieldSizeId         int = 1
	FieldSizeLastGen    int = 1 // source
	FieldSizeOverlap    int = 1 // source
	FieldSizeGenId      int = 1 // coded
	FieldSizeGenSize    int = 1 // coded
	// FieldSizeSeed    // This will depend on the scheme

	SrcHeaderSize    int = FieldSizeTypeScheme + FieldSizeId + FieldSizeLastGen + FieldSizeOverlap
	CodPreHeaderSize int = FieldSizeTypeScheme + FieldSizeId + FieldSizeGenId + FieldSizeGenSize
	LenOfSrcLen      int = 2 // COD payload header, shows decoded SRC length

	OverheadNoCoeff int = CodPreHeaderSize + LenOfSrcLen + 1 /*1st byte*/
	OverheadMax     int = OverheadNoCoeff + int(MaxGenSize)
)

var seedFieldMaxSizeUpdate int

const ( //---------------------------------------------------------------- FieldPos
	FieldPosTypeScheme int = 0
	FieldPosId         int = FieldPosTypeScheme + FieldSizeTypeScheme
	FieldPosLastGen    int = FieldPosId + FieldSizeId           // source
	FieldPosOverlap    int = FieldPosLastGen + FieldSizeLastGen // source
	FieldPosGenId      int = FieldPosId + FieldSizeId           // coded
	FieldPosGenSize    int = FieldPosGenId + FieldSizeGenId     // coded
	FieldPosSeed       int = FieldPosGenSize + FieldSizeGenSize // coded
)

////////////////////////////////////////////////////////////////////////// Masks & Flags
const (
	MaskType   uint8 = 0x80
	MaskScheme uint8 = 0x7F
	// When receivedPacked is processed, rQUIC type/scheme field is reused
	FlagObsolete uint8 = 0x01
	FlagCoded    uint8 = 0x02
	FlagSource   uint8 = 0x04 // Marks both source and decoded packets
)

////////////////////////////////////////////////////////////////////////// Min & Max
const (
	MaxGf       int     = 255 // GF(2**8)
	MaxGenSize  uint8   = 63  // The bigger, the smaller SRC size in RLNC
	MinRatio    float64 = 8   // (g+r)(1-a) >= g; a = 11% --> g/r <= 8.0909
	MaxRatio    float64 = 255 // MaxGenSize // ?
	RxRedunMarg float64 = 2   // If more COD than this --> Pollution!
	GenMargin   uint8   = 1   // Older generations than the last one to keep
)

////////////////////////////////////////////////////////////////////////// functions

func PldLenRead(slice []byte, ind int) (pldLen int) {
	for i := 0; i < LenOfSrcLen; i++ {
		pldLen = pldLen<<8 + int(slice[ind])
		ind++
	}
	return
}

func PldLenPrepare(pldLen int) []byte {
	if pldLen == 0 {
		return make([]byte, LenOfSrcLen)
	}
	slice := make([]byte, LenOfSrcLen)
	for i := LenOfSrcLen - 1; i >= 0; i-- {
		slice[i] = byte(pldLen % 256)
		pldLen >>= 8
	}
	return slice
}

func Overhead() int {
	return OverheadNoCoeff + seedFieldMaxSizeUpdate
}

func SeedFieldMaxSizeUpdate(n int) {
	seedFieldMaxSizeUpdate = n
}
