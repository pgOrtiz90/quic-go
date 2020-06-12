package rdecoder

import (
	"github.com/lucas-clemente/quic-go/rquic"
)

func (d *Decoder) lenNotProtected() int { return d.lenDCID + rquic.SrcHeaderSize }
func (d *Decoder) rQuicHdrPos() int     { return 1 /*1st byte*/ + d.lenDCID }
func (d *Decoder) rQuicSrcPldPos() int  { return 1 /*1st byte*/ + d.lenDCID + rquic.SrcHeaderSize }

func idLolderR(older, newer uint8) bool {
	// ">=" older, ">" older or equal
	return (newer - older) > 128
}

func (d *Decoder) isObsoleteId(id uint8) bool {
	// id == d.obsoleteXhold --> id is still valid
	return (d.obsoleteXhold - id) > 128
}

func (d *Decoder) isObsoletePkt(pkt parsedPacket) bool {
	//         | ,--- obsoleteXhold
	//   [* * *|* * * * * * *] --- COD.coeffs, each protects its SRC
	//   /     |           /
	//  /                 /
	//  coeff[0]         coeff[last]
	//   Oldest             Newest
	return (d.obsoleteXhold - pkt.OldestPkt()) > 128
}

// isObsoletePktAndUpdateXhold detects obsolete packets and updates d.obsoleteXhold,
// which is used for recovery operations.
//
// This method has to be executed after updating lastSeenGen with d.updateScope(parsedPacket)
func (d *Decoder) isObsoletePktAndUpdateXhold(pkt parsedPacket) bool {
	// XXXX XXXX XXXX XXXX ------------------------------GenF   ________ Packets from previous gen-s are obsolete
	//      XXXX XXXX XXXX XXXX -------------------------GenE       } Margin, not obsolete yet
	//      T    XXXX XXXX XXXX   XXXX ------------------GenD   |\
	//      |         XXXX XXXX   XXXX XXXX -------------GenC   || Packets from these gen-s
	//      |              XXXX   XXXX XXXX XXXX --------GenB   || are not obsolete
	//  the oldest                XXXX XXXX XXXX XXXX ---GenA   |/
	//  valid pkt                \--- lastSeenGen ---/
	//
	// Any packet belongs to [overlap] generations, pkt.OldestGen() = pkt.NewestGen() - (overlap - 1)
	// var obsolete bool = pkt.OldestGen() < lastValidGen // In this example, lastValidGen := GenE
	//                     pkt.NewestGen() - (overlap - 1) < lastSeenGen - (overlap - 1) - Margin
	//                     pkt.NewestGen() < lastSeenGen - Margin
	// var L, R *int*; idLolderR(L,R) = (L <= R) = !(R < L) = (L < R+1) = (L-1 < R)
	// (R < L) = !idLolderR(L, R)
	//
	obsolete := !idLolderR(d.lastSeenGen-rquic.GenMargin, pkt.NewestGen())
	if obsolete {
		if id := pkt.OldestPkt(); !d.isObsoleteId(id) {
			d.obsoleteXhold = id
		}
	}
	return obsolete
}

// updateScope updates lastSeenPkt and lastSeenGen
func (d *Decoder) updateScope(pkt parsedPacket) bool {
	sawNewPkt := pkt.NewestPkt()
	sawNewGen := pkt.NewestGen()
	if idLolderR(d.lastSeenPkt, sawNewPkt) {
		d.lastSeenPkt = sawNewPkt
		if idLolderR(d.lastSeenGen, sawNewGen) {
			d.lastSeenGen = sawNewGen
		}
		return true // d.lastSeen* updated
	}
	return false // d.lastSeen* not updated
}

func (d *Decoder) handleObsoleteSrc(ind int) bool /*there are more SRCs after ind*/ {
	for d.isObsoletePkt(d.pktsSrc[ind]) {
		d.pktsSrc[ind].markAsObsolete()
		d.removeSrcNoOrder(ind)
		if ind >= len(d.pktsSrc) {
			return false
		}
	}
	return true
}

func (d *Decoder) handleObsoleteCod(ind int) bool /*there are more CODs after ind*/ {
	if ind <= d.obsoleteCodCheckedInd {
		return ind < len(d.pktsCod)
	}
	d.obsoleteCodCheckedInd = ind
	for d.isObsoletePkt(d.pktsCod[ind]) {
		d.pktsCod[ind].markAsObsolete()
		d.removeCodNoOrder(ind)
		if ind >= len(d.pktsCod) {
			return false
		}
	}
	return true
}

func (d *Decoder) removeSrcNoOrder(ind int) {
	// https://stackoverflow.com/a/37335777
	last := len(d.pktsSrc) - 1
	if ind != last {
		d.pktsSrc[ind] = d.pktsSrc[last]
	}
	d.pktsSrc[last] = nil // prevent memory leaks
	d.pktsSrc = d.pktsSrc[:last-1]
}

func (d *Decoder) removeCodNoOrder(ind int) {
	// https://stackoverflow.com/a/37335777
	last := len(d.pktsCod) - 1
	if ind != last {
		d.pktsCod[ind] = d.pktsCod[last]
	}
	d.pktsCod[last] = nil // prevent memory leaks
	d.pktsCod = d.pktsCod[:last-1]
}

func (d *Decoder) srcAvblUpdate(id uint8) (repeatedSrc bool) {
	// Obsolete elements are removed in another method
	for i := len(d.srcAvbl) - 1; i >= 0; i-- {
		if idLolderR(d.srcAvbl[i], id) {
			d.srcAvbl = append(append(d.srcAvbl[:i+1], id), d.srcAvbl[i+1:]...)
			return
		}
		if d.srcAvbl[i] == id { // pkt already received
			return true
		}
	}
	// At this point, id must be the oldest id in the list
	d.srcAvbl = append([]uint8{id}, d.srcAvbl...)
	return
}

func (d *Decoder) srcMissUpdate() {
	// If multiple redun-s per gen., do not repeat this action.
	d.doCheckMissingSrc = false // becomes true after d.lastSeenPkt update by new COD

	// Remove obsolete pkt ids from srcAvbl list
	if d.isObsoleteId(d.srcAvbl[0]) {
		for i := 1; i < len(d.srcAvbl); i++ {
			if !d.isObsoleteId(d.srcAvbl[i]) {
				d.srcAvbl = d.srcAvbl[i:]
				break
			}
		}
	}

	// Redefine d.srcMiss, return if nothing is missing
	maxId := d.lastSeenPkt + 1
	srcMissLen := int(maxId-d.obsoleteXhold) /*expected SRC*/ - len(d.srcAvbl)
	d.srcMiss = d.srcMiss[:srcMissLen]
	if srcMissLen == 0 {
		return
	} // nothing to do

	// Check which expected SRC IDs haven't been received
	var indAv, indMiss int
	for missId := d.obsoleteXhold; idLolderR(missId, maxId); missId++ {
		if d.srcAvbl[indAv] == missId {
			indAv++
			if indAv == len(d.srcAvbl) {
				for indMiss < srcMissLen {
					missId++
					d.srcMiss[indMiss] = missId
					indMiss++
				}
				return
			}
		} else {
			d.srcMiss[indMiss] = missId
			indMiss++
			if indMiss == srcMissLen {
				return
			}
		}
	}
}
