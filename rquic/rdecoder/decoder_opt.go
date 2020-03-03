package rdecoder

func (d *Decoder) optimizeWithSrc(src *parsedSrc) {
	var cod *parsedCod
	for i := 0; i < len(d.pktsCod); i++ {
		// Remove obsolete COD
		//         | ,--- obsoleteXhold
		//   [* * *|* * * * * * *]
		//   /     |           /
		//  /                 /
		//  coeff[0]         coeff[last]
		//          Which one?
		for d.isObsolete(d.pktsCod[i].coeff[0]) { //coeff[d.pktsCod[i].last()]) {
			d.removeCodNoOrder(i)
		}
		cod = d.pktsCod[i]
		// Remove SRC from COD, if COD protects it
		if ind, ok := cod.findSrcId(src.id); ok {
			cod.removeSrc(src, ind)
			// If COD decoded, prepare new SRC
			cod.remaining--
			// Remove only 1 SRC --> reslicing, not cod.wipeZeros
			cod.coeff = append(cod.coeff[:i], cod.coeff[i+1:]...)
			cod.srcIds = append(cod.srcIds[:i], cod.srcIds[i+1:]...)
			if cod.remaining == 1 {
				if ns := d.NewSrcRec(cod); ns != nil {
					d.optimizeWithSrc(ns)
				}
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
		for d.isObsolete(d.pktsSrc[i].id) {
			d.removeSrcNoOrder(i) // remove obsolete SRC
		}
		if notFull { // main for loop is not broken for obsolete SRC removal
			if ind, ok := cod.findSrcId(d.pktsSrc[i].id); ok {
				availableSrc = append(availableSrc, d.pktsSrc[i])
				inds = append(inds, ind)
				notFull = len(availableSrc) < cod.remaining
			}
		}
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

	cod.scaleDown()
	if ns := d.NewSrcRec(cod); ns != nil {
		d.optimizeWithSrc(ns)
	}

	return
}
