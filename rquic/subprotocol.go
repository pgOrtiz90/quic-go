package rquic

////////////////////////////////////////////////////////////////////////// Type & Scheme
const (
	TypeUnprotected uint8 = iota // 0x00
	TypeProtected
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
	TypeUnknown
)
const TypeCoded uint8 = TypeProtected + 1 // any value b/w TypeProtected and TypeUnknown
var SchemesReader = map[string]uint8{
	"SchemeXor":    SchemeXor,
	"SchemeRlcSys": SchemeRlcSys,
}
var SchemesExplainer = map[uint8]string{
	SchemeXor:    "SchemeXor",
	SchemeRlcSys: "SchemeRlcSys",
}

////////////////////////////////////////////////////////////////////////// Field
// SRC
//    [   1st byte   ]
//    [                 Destination Connection ID                    ]
//    [     type     ][    pkt id    ][ last gen. id ][   overlap    ]
// COD
//    [   1st byte   ]
//    [                 Destination Connection ID                    ]
//    [     type     ][    pkt id    ][    gen id    ][  gen.  size  ]
//    [ seed / coeff   ... ... ... ... ... ... ... ... ... ... ... ...
//    ...  up to GenSizeMax * n (n /*coeff size*/ = /*always(?)*/ 1) ]
const ( //---------------------------------------------------------------- FieldSize
	FieldSizeType    int = 1
	FieldSizeId      int = 1
	FieldSizeLastGen int = 1 // source
	FieldSizeOverlap int = 1 // source
	FieldSizeGenId   int = 1 // coded
	FieldSizeGenSize int = 1 // coded
	// FieldSizeSeed    // This will depend on the scheme

	SrcHeaderSize      int = FieldSizeType + FieldSizeId + FieldSizeLastGen + FieldSizeOverlap
	CodPreHeaderSize   int = FieldSizeType + FieldSizeId + FieldSizeGenId + FieldSizeGenSize
	LenOfSrcLen        int = 2 // COD payload header, shows decoded SRC length
	CodedOverhead      int = LenOfSrcLen + 1 // Pld len. and 1st byte are protected and inserted b/w rQUIC hdr & pld

	OverheadNoCoeff  int = CodPreHeaderSize + LenOfSrcLen + 1 /*1st byte*/
	OverheadMax      int = OverheadNoCoeff + int(GenSizeMax)
	CodHeaderSizeMax int = CodPreHeaderSize + int(GenSizeMax)
)

var seedFieldMaxSize int

const ( //---------------------------------------------------------------- FieldPos
	FieldPosType    int = 0
	FieldPosId      int = FieldPosType + FieldSizeType
	FieldPosLastGen int = FieldPosId + FieldSizeId           // source
	FieldPosOverlap int = FieldPosLastGen + FieldSizeLastGen // source
	FieldPosGenId   int = FieldPosId + FieldSizeId           // coded
	FieldPosGenSize int = FieldPosGenId + FieldSizeGenId     // coded
	FieldPosSeed    int = FieldPosGenSize + FieldSizeGenSize // coded
)

////////////////////////////////////////////////////////////////////////// Flags
// When receivedPacked is processed, rQUIC type/scheme field is reused
const (
	FlagObsolete uint8 = 0x01
	FlagCoded    uint8 = 0x02
	FlagSource   uint8 = 0x04 // Marks both source and decoded packets
)

////////////////////////////////////////////////////////////////////////// Min & Max
const (
	MaxGf       int     = 255                 // GF(2**8)
	GenSizeMax  uint8   = 63                  // The bigger, the smaller SRC size in RLNC
	MinRatio    float64 = 2                   // (g+r)(1-a) >= g; R = g/r <= (1-a)/a; a <= 1/(R+1)
	MaxRatio            = float64(GenSizeMax) // 255 or GenSizeMax ?
	RxRedunMarg float64 = 2                   // If more COD than this --> Pollution!
	GenMargin   uint8   = 1                   // Older generations than the last one to keep
	AgeDiffMax  uint8   = 1 << (8 - 1)        // The amount of pkt IDs
)

// Max range of current packets.
// newestPkt.ID - AgeDiff + 1 <= Pkt.ID <= newestPkt.ID
// Packet IDs out of this range are considered obsolete.
var AgeDiff uint8 = AgeDiffMax

// AgeDiffSet calculates a reasonable value for AgeDiff, which
// may vary throughout experiments. AgeDiff will be assigned
// the minimum between the new value and AgeDiffMax.
func AgeDiffSet() {
	// Packets from present and overlapped generations:
	// UsefulPackets := genSize + (overlap - 1) * (genSize / overlap) = 2 * genSize - 1/overlap
	// As the overlap increases, UsefulPackets will tend to 2 * genSize
	ageDiffReasonable := (2 + int(GenMargin)) * int(GenSizeMax)
	if int(AgeDiffMax) < ageDiffReasonable {
		AgeDiff = AgeDiffMax
		return
	}
	AgeDiff = byte(ageDiffReasonable)
}

func IdLeftOlderEqRight(older, newer byte) bool {
	return (newer - older) < AgeDiff
}

func IdLeftOlderRight(older, newer byte) bool {
	if newer == older {
		return false
	}
	return (newer - older) < AgeDiff
}

////////////////////////////////////////////////////////////////////////// Payload length {en, de}code

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
	return OverheadNoCoeff + seedFieldMaxSize
}

func SeedFieldMaxSizeUpdate(n int) {
	seedFieldMaxSize = n
}
