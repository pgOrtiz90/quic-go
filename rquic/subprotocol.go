package rquic

////////////////////////////////////////////////////////////////////////// Scheme
const (
	SchemeNoCode uint8 = iota 	// 0x00
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
)

////////////////////////////////////////////////////////////////////////// Field
// [   1st byte   ]
// [                 Destination Connection ID                    ]
// [ type  scheme ][    pkt id    ][  gen.  size  ][ seed / coeff ]
const (
    FieldSizeTypeScheme int = 1                                         // FieldSize
    FieldSizeId         int = 1
    FieldSizeGenSize    int = 1
    // FieldSizeSeed    // This will depend on the scheme
    
    SrcHeaderSize int = FieldSizeTypeScheme + FieldSizeId
    CodPreHeaderSize int = FieldSizeTypeScheme + FieldSizeId + FieldSizeGenSize
)
const (                                                                 // FieldPos
    FieldPosTypeScheme  int = 0
    FieldPosId          int = FieldPosTypeScheme + FieldSizeTypeScheme
    FieldPosGenSize     int = FieldPosId         + FieldSizeId
    FieldPosSeed        int = FieldPosGenSize    + FieldSizeGenSize
)

////////////////////////////////////////////////////////////////////////// Mask
const (
    MaskType    uint8 = 0x80
    MaskScheme  uint8 = 0x7F
)

////////////////////////////////////////////////////////////////////////// Min & Max
const (
    MaxGf       int = 255 // GF(2**8)
    MaxGenSize  uint8 = 64    // The bigger, the smaller goodput in RLNC
    MinRatio    float64 = 8 // (g+r)(1-a) >= g; a = 11% --> g/r <= 8.0909
    RxRedunMarg float64 = 2 // If more COD than this --> Pollution!
)
