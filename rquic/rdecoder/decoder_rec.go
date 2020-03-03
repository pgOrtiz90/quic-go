package rdecoder

func (d *Decoder) Recover() {
	if len(d.pktsCod) < 2 {
		return
	} // Nothing to do

	if d.doCheckMissingSrc {
		d.srcMissUpdate()
	}

	var cod *parsedCod
	var topRow, r, ind int
	numRows := len(d.pktsCod)

	for _, id := range d.srcMiss { //  Top-down
		//    1XXX          1XXX
		//      1XX           1XX
		//        XXX          1XX
		//        XXX           1XX
		//      XXXX             1X
		//        XXX             1
		//           XXX           1XX
		//           XXX            1X

		// find non-zero element in column
		r = topRow
		for r < numRows {
			if _, ok := d.pktsCod[r].findSrcId(id); ok {
				cod = d.pktsCod[r]
				break
			}
			r++
		}

		if r < topRow {
			// swap
			d.pktsCod[r] = d.pktsCod[topRow]
			d.pktsCod[topRow] = cod
			// scale the row
			cod.scaleDown()
			// subtract scaled row from other rows with non-zero element
			r++
			for r < numRows {
				d.pktsCod[r].attachCod(cod, 0)
				r++
			}

			topRow++
			if topRow >= numRows {
				break
			}
		}
	}

	topRow = numRows - 1
	for topRow >= 0 { //  Bottom-up
		//    1XXX          1X
		//      1XX           1
		//       1XX           1
		//        1XX           1
		//         1X            1
		//          1             1
		//           1XX           1Y
		//            1X            1X

		cod = d.pktsCod[topRow]
		cod.wipeZeros()
		if cod.remaining == 0 {
			d.removeCodNoOrder(topRow)
		} else {
			ind = cod.last()
			for i := 0; i < topRow; i++ {
				// 0 <= d.pktsCod[i].srcIds[0] - cod.srcIds[0] < 128
				d.pktsCod[i].attachCod(cod, ind)
			}
			if cod.remaining == 1 {
				d.NewSrcRec(cod)
				d.removeCodNoOrder(topRow)
				// TODO: think about updating d.srcMiss rather than rebuilding or ignoring it
			}
		}
		topRow--
	}
}
