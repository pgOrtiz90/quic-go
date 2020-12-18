package rdecoder

import "github.com/lucas-clemente/quic-go/rquic/rLogger"

func (d *Decoder) optimizeWithSrc(src *parsedSrc, obsoleteCodNewCheck bool) {
	var cod *parsedCod
	if obsoleteCodNewCheck {
		d.obsoleteCodCheckedInd = 0
	}

	rLogger.Debugf("Decoder OptimizeSrc Pkt.ID:%d", src.id)

	for i := 0; i < len(d.pktsCod); {
		if moreCod := d.handleObsoleteCod(i); !moreCod {
			return
		}
		// Remove SRC from COD, if COD protects it
		cod = d.pktsCod[i]
		if ind, ok := cod.findSrcId(src.id); ok {
			cod.remaining--
			if cod.remaining == 0 {
				d.removeCodNoOrder(i)
				cod.markAsObsolete()
				continue
			}
			cod.removeSrc(src, ind)
			// Remove only 1 SRC --> reslicing, not cod.wipeZeros
			cod.coeff = append(cod.coeff[:i], cod.coeff[i+1:]...)
			cod.srcIds = append(cod.srcIds[:i], cod.srcIds[i+1:]...)
			if cod.remaining == 1 {
				// This COD will be used as SRC or become useless.
				// Remove it before any other method will try to use it.
				d.removeCodNoOrder(i)
				if ns := d.NewSrcRec(cod); ns != nil {
					d.optimizeWithSrc(ns, false)
				} else {
					cod.markAsObsolete() // New SRC is obsolete or duplicate. Remove from buffer.
				}
				continue
			}
		}
		i++
	}
}

func (d *Decoder) optimizeThisCodAim(cod *parsedCod) (availableSrc []*parsedSrc, inds []int, notFull bool) {
	availableSrc = make([]*parsedSrc, 0, cod.remaining)
	inds = make([]int, 0, cod.remaining)
	notFull = true

	defer func() {
		rLogger.Debugf("Decoder OptimizeCod gen.ID:%d pkt.ID:%d RxSrc:%d/%d",
			cod.genId, cod.id, len(availableSrc), cod.remaining,
		)
		if !notFull {
			cod.markAsObsolete()
		}
	}()

	for i := 0; i < len(d.pktsSrc); i++ {
		if moreSrc := d.handleObsoleteSrc(i); !moreSrc {
			return
		}
		if notFull {
			if ind, ok := cod.findSrcId(d.pktsSrc[i].id); ok {
				availableSrc = append(availableSrc, d.pktsSrc[i])
				inds = append(inds, ind)
				notFull = len(availableSrc) < cod.remaining
			}
		} else if d.obsoleteSrcChecked {
			return
		}
		// main for loop is not broken for obsolete SRC removal
	}
	d.obsoleteSrcChecked = true

	return
}

func (d *Decoder) optimizeThisCodFire(cod *parsedCod, srcs []*parsedSrc, inds []int) (codIsUseful bool) {

	for i, ind := range inds {
		cod.removeSrc(srcs[i], ind)
		cod.coeff[ind] = 0
	}
	cod.wipeZeros()

	codIsUseful = cod.remaining > 1
	if codIsUseful {
		return
	}
	// if !codIsUseful --> cod.remaining == 1; cod.remaining == 0 --> this method is not called

	if ns := d.NewSrcRec(cod); ns != nil {
		d.optimizeWithSrc(ns, true)
	}
	// When this method is called, COD is not stored yet, no need(way) to remove it from pktsCod.

	return
}
