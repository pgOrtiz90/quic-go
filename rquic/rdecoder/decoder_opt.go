package rdecoder

import "github.com/lucas-clemente/quic-go/rquic/rLogger"

func (d *Decoder) optimizeWithSrc(src *parsedSrc, srcIndOffset int) {
	var cod *parsedCod

	if rLogger.IsDebugging() {
		rLogger.Printf("Decoder OptimizeSrc Pkt.ID:%d", src.id)
	}

	for i := 0; i < len(d.pktsCod); i++ {
		if i >= srcIndOffset {
			for d.isObsoletePkt(d.pktsCod[i]) {
				d.removeCodNoOrder(i)
				d.pktsCod[i].markAsObsolete()
			}
		}
		cod = d.pktsCod[i]
		// Remove SRC from COD, if COD protects it
		if ind, ok := cod.findSrcId(src.id); ok {
			cod.remaining--
			if cod.remaining == 0 {
				d.removeCodNoOrder(i)
				cod.markAsObsolete()
				i--
				continue
			}
			cod.removeSrc(src, ind)
			// Remove only 1 SRC --> reslicing, not cod.wipeZeros
			cod.coeff = append(cod.coeff[:i], cod.coeff[i+1:]...)
			cod.srcIds = append(cod.srcIds[:i], cod.srcIds[i+1:]...)
			if cod.remaining == 1 {
				if ns := d.NewSrcRec(cod); ns != nil {
					d.removeCodNoOrder(i)
					d.optimizeWithSrc(ns, i+1)
					// Previous call to optimizeWithSrc has finished obsolete packet check. Stop checking.
					srcIndOffset = len(d.pktsCod)
				}
				// COD is decoded and converted to SRC, remove it from the list of COD
				d.removeCodNoOrder(i)
				i--
			}
		}
	}
}

func (d *Decoder) optimizeThisCodAim(cod *parsedCod) (availableSrc []*parsedSrc, inds []int, notFull bool) {
	availableSrc = make([]*parsedSrc, 0, cod.remaining)
	inds = make([]int, 0, cod.remaining)
	notFull = true

	for i := 0; i < len(d.pktsSrc); i++ {
		for d.isObsoletePkt(d.pktsSrc[i]) {
			d.pktsSrc[i].markAsObsolete()
			d.removeSrcNoOrder(i)
		}
		if i >= len(d.pktsSrc) {
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
	if rLogger.IsDebugging() {
		rLogger.Printf("Decoder OptimizeCod gen.ID:%d pkt.ID:%d RxSrc:%d/%d",
			cod.genId, cod.id, len(availableSrc), cod.remaining,
		)
	}

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
		if rLogger.IsDebugging() {
			rLogger.Printf("Decoder OptimizeCod Optimized remaining:%d", cod.remaining)
		}
		d.optimizeWithSrc(ns, 0)
	}
	// When this method is called, COD is not stored yet, no need(way) to remove it from pktsCod.

	return
}
