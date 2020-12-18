package rdecoder

import "github.com/lucas-clemente/quic-go/rquic/rLogger"

func (d *Decoder) Recover() {
	numRows := len(d.pktsCod)

	if rLogger.IsDebugging() {
		rLogger.Printf("Decoder Recovery Initiated NumCodPkts:%d MissingSrc:%d", numRows, d.srcMiss)
		defer rLogger.Printf("Decoder Recovery Finished")
	}

	if numRows < 2 /* not enough CODs */ || len(d.srcMiss) == 0 /* no SRC is missing */ {
		return
	}

	var cod *parsedCod
	var topRow, r, ind int
	// numRows := len(d.pktsCod) // Moved upwards

	//--------- Top-down ---------
	//    1XXX          1XXX
	//      1XX           1XX
	//        XXX          1XX
	//        XXX           1XX
	//      XXXX             1X
	//        XXX             1
	//           XXX           1XX
	//           XXX            1X
	for _, id := range d.srcMiss {
		// find non-zero element in column
		for r = topRow; r < numRows; r++ {
			if _, ok := d.pktsCod[r].findSrcId(id); ok {
				cod = d.pktsCod[r]
				rLogger.Debugf("Decoder Recovery TopDown Row:%d srcIDs:%d coeffs:%d", r, cod.srcIds, cod.coeff)
				break
			}
		}
		if r == numRows {
			// No more rows with this id
			//        v--------- id
			//      1XXXX
			//       1XXX
			//           XXXX <- topRow
			//           XXXX _________
			// r ->            numRows
			// TODO: consider iterating over rows & looking for the oldest cod.srcIds[0] for each swap
			continue
		}
		// swap
		if topRow < r {
			d.pktsCod[r] = d.pktsCod[topRow]
			d.pktsCod[topRow] = cod
		}
		// scale the row
		cod.scaleDown()
		// log swap&scale
		rLogger.Debugf("Decoder Recovery SwapScale NewRow:%d coeffs:%d", topRow, cod.coeff)
		// subtract scaled row from other rows with non-zero element
		for r++; r < numRows; r++ {
			rLogger.Debugf("Decoder Recovery AttachCod TgtRow:%d", r)
			d.pktsCod[r].attachCod(cod, 0)
		}

		topRow++
		if topRow >= numRows {
			break
		}
	}

	//-------- Bottom-up ---------
	//    1XXX          1X
	//      1XX           1
	//       1XX           1
	//        1XX           1
	//         1X            1
	//          1             1
	//           1XX           1Y
	//            1X            1X
	for topRow = numRows - 1; topRow >= 0; topRow-- {
		cod = d.pktsCod[topRow]
		rLogger.Debugf("Decoder Recovery BottomUp Row:%d", topRow)
		if cod.remaining == 0 {
			d.removeCodNoOrder(topRow)
			cod.markAsObsolete()
		} else {
			ind = len(cod.coeff) - 1
			for i := 0; i < topRow; i++ {
				// 0 <= d.pktsCod[i].srcIds[0] - cod.srcIds[0] < 128
				rLogger.Debugf("Decoder Recovery AttachCod TgtRow:%d", i)
				d.pktsCod[i].attachCod(cod, ind)
			}
			if cod.remaining == 1 {
				d.NewSrcRec(cod)
				d.removeCodNoOrder(topRow)
			}
		}
	}
}
