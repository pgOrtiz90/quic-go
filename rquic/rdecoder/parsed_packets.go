package rdecoder

import (
    "github.com/lucas-clemente/quic-go/rquic/gf"
)



type parsedSrc struct {
    id      uint8
    pld     []byte
}



type parsedCod struct {
    // id          uint8 // is not necessary after srcIds are generated
    // scheme      uint8 // is not necessary after decoder.lastScheme is updated
    // genSize     int   // is not necessary after remaining is defined
    remaining   int
    
    coeff       []uint8
    srcIds      []uint8
    
    pld         []byte
}

func (c *parsedCod) last() int {
    return len(c.coeff)-1
}

func (c *parsedCod) lastId() uint8 {
    return c.srcIds[len(c.srcIds)-1]
}

func (c *parsedCod) findSrcId(id uint8) (int, bool) {
    if idLolderR(id, c.srcIds[0]) || idLolderR(c.lastId(), id) {
        return 0, false
    }
    // https://yourbasic.org/golang/find-search-contains-slice/
    for i, n := range c.srcIds {
        if id == n {
            if c.coeff[i] != 0 {
                return i, true
            }
        }
    }
    // Intermediate coefficients could have been optimized out
    return 0, false
}

func (c *parsedCod) removeSrc (src *parsedSrc, ind int) {
    cf := c.coeff[ind]
    if cf == 1 {
        for i, v := range src.pld {
            c.pld[i] ^= v
        }
    } else {
        for i, v := range src.pld {
            c.pld[i] ^= gf.Mult(cf, v)
        }
    }
}

func (c *parsedCod) wipeZeros() {
    newCoeff  := make([]uint8, 0, len(c.coeff))
    newSrcIds := make([]uint8, 0, len(c.coeff))
    for i, cf := range c.coeff {
        if cf != 0 {
            newCoeff  = append(newCoeff,  cf         )
            newSrcIds = append(newSrcIds, c.srcIds[i])
        }
    }
    c.coeff  = newCoeff
    c.srcIds = newSrcIds
    
    c.remaining = len(c.coeff)
    if c.remaining == 1 {c.scaleDown()}
}

func (c *parsedCod) scaleDown() {
    if c.coeff[0] == 1 {return}
    cf := gf.Div(1, c.coeff[0])
    c.coeff[0] = 1
    for i := 1; i < len(c.coeff); i++ {
        c.coeff[i] = gf.Mult(c.coeff[i], cf)
    }
    for i, v := range c.pld {
        c.pld[i] = gf.Mult(v, cf)
    }
}

func (c *parsedCod) attachCod(cod *parsedCod, codInd int) {
    //  Use cases:
    //    [1] Top-down                  [2] Bottom-up
    //        1XXX          1XXX            1XXX          1X
    //          1XX    cod    1XX             1XX           1
    //            XXX   |      1XX             1XX           1
    //            XXX   |       1XX             1XX      <    1
    //          XXXX    <        1X              1X      |     1
    //            XXX             1               1     cod     1
    //               XXX           1XX             1XX     <     1 Y
    //               XXX            1X              1X    cod     1X
    //    
    //  0 <= c.srcIds[0] - cod.srcIds[0] < 128
    
    ind, ok := c.findSrcId(cod.srcIds[codInd])
    if !ok {return}
    
    j := 0 // aux. var. for iteration over  --< cod.srcIds >--
    
    cf := gf.Div(c.coeff[ind], cod.coeff[codInd])
    
    if cf != 1 {
        // Update coefficients
        for i := 0; i < len(c.srcIds); i++ {
            if cod.srcIds[j] == c.srcIds[i] {
                c.coeff[i] ^= gf.Mult(cod.coeff[j], cf)
                j++
                // i++
            } else if c.srcIds[i] > cod.srcIds[j] {
                if cod.coeff[j] > 0 {
                    c.srcIds = append(append(c.srcIds[:i], cod.srcIds[j]            ), c.srcIds[i:]...)
                    c.coeff  = append(append(c.coeff[:i] , gf.Mult(cod.coeff[j], cf)), c.coeff[i:]... )
                    j++
                }
            }
            // if c.srcIds[i] < cod.srcIds[j] {i++}
            if j == len(cod.srcIds) {break}
        }
        if d := len(cod.srcIds) - j; d > 0 {
            prevLen := len(c.coeff)
            c.srcIds = append(c.srcIds, cod.srcIds[j:]...)
            c.coeff  = append(c.coeff , make([]uint8, d)...)
            for i := prevLen; i < len(c.coeff); i++ {
                c.coeff[i] = gf.Mult(cod.coeff[j], cf)
                j++
            }
        }
        // Update payload
        if diffLen := len(cod.pld) - len(c.pld); diffLen > 0 {
            c.pld = append(c.pld, make([]uint8, diffLen)...)
        }
        for i, v := range cod.pld { 
            c.pld[i] ^= gf.Mult(v, cf)
        } // '^=' seems faster than '=' for uint8 in go1.13 linux/amd64
        return
    } // else {
        // Update coefficients
        for i := 0; i < len(c.srcIds); i++ {
            if cod.srcIds[j] == c.srcIds[i] {
                c.coeff[i] ^= cod.coeff[j]
                j++
                // i++
            } else if c.srcIds[i] > cod.srcIds[j] {
                if cod.coeff[j] > 0 {
                    c.srcIds = append(append(c.srcIds[:i], cod.srcIds[j]), c.srcIds[i:]...)
                    c.coeff  = append(append(c.coeff[:i] , cod.coeff[j] ), c.coeff[i:]... )
                    j++
                }
            }
            // if c.srcIds[i] < cod.srcIds[j] {i++}
            if j == len(cod.srcIds) {break}
        }
        if d := len(cod.srcIds) - j; d > 0 {
            c.srcIds = append(c.srcIds, cod.srcIds[j:]...)
            c.coeff  = append(c.coeff , cod.coeff[j:]... )
        }
        // Update payload
        loopLim := len(cod.pld)
        if len(c.pld) < loopLim {
            loopLim = len(c.pld)
            c.pld = append(c.pld, cod.pld[loopLim:]...)
        }
        for i := 0; i < loopLim; i++ { 
            c.pld[i] ^= cod.pld[i]
        }
        // return
    // }
}
