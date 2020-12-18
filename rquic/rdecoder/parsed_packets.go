package rdecoder

import (
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/gf"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type parsedSrc struct {
	id       uint8
	lastGen  uint8
	overlap  uint8
	fwd      *byte
	pld      []byte
	ovh2code []byte
}

func (s *parsedSrc) obsoleteCheckInputs() (uint8, uint8) { return s.id, s.lastGen }

func (s *parsedSrc) markAsObsolete() {
	*s.fwd |= rquic.FlagObsolete
	rLogger.Debugf("Decoder ObsoleteSrc gen.ID:%d pkt.ID:%d", s.lastGen, s.id)
}

type parsedCod struct {
	// scheme      uint8 // is not necessary after Decoder.lastScheme is updated
	id        byte // not necessary, but good for logging
	genSize   byte // is not necessary after remaining is defined // good for logging
	remaining int

	coeff  []uint8
	srcIds []uint8
	genId  uint8
	fwd    *byte
	rid    *byte

	pld       []byte
	codedOvh  []byte
	codedPld  []byte
}

func (s *parsedCod) obsoleteCheckInputs() (uint8, uint8) { return s.srcIds[0], s.genId }

func (c *parsedCod) markAsObsolete() {
	*c.fwd |= rquic.FlagObsolete
	rLogger.Debugf("Decoder ObsoleteCod gen.ID:%d pkt.ID:%d", c.genId, c.id)
}

func (c *parsedCod) findSrcId(id uint8) (int, bool) {
	if len(c.srcIds) == 0 {
		return 0, false
	}
	if rquic.IdLeftOlderRight(id, c.srcIds[0]) || rquic.IdLeftOlderRight(c.srcIds[len(c.srcIds)-1], id) {
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

func (c *parsedCod) removeSrc(src *parsedSrc, ind int) {
	cf := c.coeff[ind]
	if cf == 1 {
		for i, v := range src.ovh2code {
			c.codedOvh[i] ^= v
		}
		cLen, sLen := len(c.codedPld), len(src.pld)
		i, endLoop := 0, utils.Min(cLen, sLen)
		for ; i < endLoop; i++ {
			c.codedPld[i] ^= src.pld[i]
		}
		if endLoop == cLen {
			return
		}
		c.pld = c.pld[:sLen]
		for ; i < sLen; i++ {
			c.codedPld[i] = src.pld[i]
		}
		return
	}
	for i, v := range src.ovh2code {
		c.codedOvh[i] ^= gf.Mult(cf, v)
	}
	cLen, sLen := len(c.codedPld), len(src.pld)
	i, endLoop := 0, utils.Min(cLen, sLen)
	for ; i < endLoop; i++ {
		c.codedPld[i] ^= gf.Mult(cf, src.pld[i])
	}
	if endLoop == cLen {
		return
	}
	c.pld = c.pld[:sLen]
	for ; i < sLen; i++ {
		c.codedPld[i] = gf.Mult(cf, src.pld[i])
	}
}

func (c *parsedCod) wipeZeros() {
	var w int
	for r, cf := range c.coeff {
		if cf != 0 {
			c.coeff[w] = cf
			c.srcIds[w] = c.srcIds[r]
			w++
		}
	}
	c.coeff = c.coeff[:w]
	c.srcIds = c.srcIds[:w]
	c.remaining = w
}

func (c *parsedCod) scaleDown() {
	if c.coeff[0] == 1 {
		return
	}
	cf := gf.Inverse(c.coeff[0])
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
	//               XXX           1XX             1XX     <     1Y
	//               XXX            1X              1X    cod     1X
	//
	//  0 <= c.srcIds[0] - cod.srcIds[0] < 128

	ind, ok := c.findSrcId(cod.srcIds[codInd])
	if !ok {
		return
	}

	if rLogger.IsDebugging() {
		rLogger.Printf("Decoder Recovery AttachCod Orig.  srcIDs:%d coeffs:%d", c.srcIds, c.coeff)
		rLogger.Printf("Decoder Recovery AttachCod Attach srcIDs:%d coeffs:%d coeffInd:%d", cod.srcIds, cod.coeff, codInd)
		defer func() {
			rLogger.Printf("Decoder Recovery AttachCod Result srcIDs:%d coeffs:%d", c.srcIds, c.coeff)
		}()
	}

	j := 0 // aux. var. for iteration over  --< cod.srcIds >--
	codCfLen := len(cod.coeff)

	cf := gf.Div(c.coeff[ind], cod.coeff[codInd])

	if cf != 1 {
		// Update coefficients
		for i := 0; i < len(c.srcIds) && j < codCfLen; {
			if c.srcIds[i] == cod.srcIds[j] {
				c.coeff[i] ^= gf.Mult(cod.coeff[j], cf)
				i++
				j++
				continue
			}
			if rquic.IdLeftOlderRight(c.srcIds[i], cod.srcIds[j]) {
				i++
				continue
			}
			//if c.srcIds[i] > cod.srcIds[j] {
				c.srcIds = append(append(c.srcIds[:i], cod.srcIds[j]), c.srcIds[i:]...)
				c.coeff = append(append(c.coeff[:i], gf.Mult(cod.coeff[j], cf)), c.coeff[i:]...)
				j++
			//	continue
			//}
		}
		if j < codCfLen {
			c.srcIds = append(c.srcIds, cod.srcIds[j:]...)
			c.coeff = append(c.coeff, make([]uint8, codCfLen-j)...)
			for i := len(c.coeff); i < codCfLen; i++ {
				c.coeff[i] = gf.Mult(cod.coeff[j], cf)
				j++
			}
		}
		// Update payload
		c.wipeZeros()
		if len(c.srcIds) == 0 {
			return
		}
		cLen, codLen := len(c.pld), len(cod.pld)
		i, endLoop := 0, utils.Min(codLen, cLen)
		for ; i < endLoop; i++ {
			c.pld[i] ^= gf.Mult(cod.pld[i], cf)
		}
		if endLoop == cLen {
			return
		}
		c.pld = c.pld[:codLen]
		for ; i < codLen; i++ {
			c.pld[i] = gf.Mult(cod.pld[i], cf)
		}
		return
	}

	// if cf == 1

	// Update coefficients
	for i := 0; i < len(c.srcIds); {
		if c.srcIds[i] == cod.srcIds[j] {
			c.coeff[i] ^= cod.coeff[j]
			i++
			j++
			continue
		}
		if rquic.IdLeftOlderRight(c.srcIds[i], cod.srcIds[j]) {
			i++
			continue
		}
		//if c.srcIds[i] > cod.srcIds[j] {
			c.srcIds = append(append(c.srcIds[:i], cod.srcIds[j]), c.srcIds[i:]...)
			c.coeff = append(append(c.coeff[:i], cod.coeff[j]), c.coeff[i:]...)
			j++
		//	continue
		//}
	}
	if j < codCfLen {
		c.srcIds = append(c.srcIds, cod.srcIds[j:]...)
		c.coeff = append(c.coeff, cod.coeff[j:]...)
	}
	// Update payload
	c.wipeZeros()
	if len(c.srcIds) == 0 {
		return
	}
	cLen, codLen := len(c.pld), len(cod.pld)
	i, endLoop := 0, utils.Min(codLen, cLen)
	for ; i < endLoop; i++ {
		c.pld[i] ^= cod.pld[i]
	}
	if endLoop == cLen {
		return
	}
	c.pld = c.pld[:codLen]
	for ; i < codLen; i++ {
		c.pld[i] = cod.pld[i]
	}
}
