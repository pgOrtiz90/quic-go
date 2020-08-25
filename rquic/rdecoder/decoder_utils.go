package rdecoder

import (
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

func (d *Decoder) offset() int { return 1 /*1st byte*/ + d.lenDCID }

func idLolderR(older, newer uint8) bool {
	// older < newer
	if newer == older {
		return false
	}
	// older <= newer
	return (newer - older) < rquic.AgeDiff
}

func (d *Decoder) isObsoletePktId(p uint8) bool {
	// p == d.obsoleteXhold --> p is still valid
	// p - d.obsoleteXhold < rquic.AgeDiffMax --> pkt ok
	return (p - d.obsoleteXhold) >= rquic.AgeDiff
}

func (d *Decoder) isObsoleteGenId(g uint8) bool {
	// g == d.lastValidGen --> g is still valid
	// g - d.lastValidGen < rquic.AgeDiffMax --> pkt ok
	return (g - d.lastValidGen) >= rquic.AgeDiff
}

// isObsolete detects obsolete packets.
// It attempts to update d.obsoleteXhold when it detects an obsolete generation.
// Use maybeUpdateXhold for updating d.obsoleteXhold based on lastSeenPkt.
// This method should be executed after lastSeen method.
func (d *Decoder) isObsolete(p, g byte) bool {
	if d.isObsoletePktId(p) {
		return true
	}
	if d.isObsoleteGenId(g) {
		if newXhold := p + 1; idLolderR(d.obsoleteXhold, newXhold) {
			d.obsoleteXhold = newXhold
		}
		return true
	}
	return false /*not obsolete*/
}

func (d *Decoder) maybeUpdateXhold() {
	if newXhold := d.lastSeenPkt - d.distToLastValidId; idLolderR(d.obsoleteXhold, newXhold) {
		d.obsoleteXhold = newXhold
	}
}

// lastSeen updates lastSeenPkt and lastSeenGen
func (d *Decoder) lastSeen(p, g byte) bool {
	if idLolderR(d.lastSeenPkt, p) {
		d.lastSeenPkt = p
		if idLolderR(d.lastSeenGen, g) {
			d.lastSeenGen = g
			// Any packet belongs to [overlap] generations. Last [overlap] + Margin generations are valid.
			lvg := d.lastValidGen
			d.lastValidGen = d.lastSeenGen - d.lastSeenOverlap - rquic.GenMargin + 1
			rLogger.Debugf("Updating lastValidGen Old:%d New:%d", lvg, d.lastValidGen)
		}
		return true // d.lastSeen* updated
	}
	return false // d.lastSeen* not updated
}

func (d *Decoder) handleObsoleteSrc(ind int) bool /*there are more SRCs after ind*/ {
	for d.isObsolete(d.pktsSrc[ind].obsoleteCheckInputs()) {
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
	for d.isObsolete(d.pktsCod[ind].obsoleteCheckInputs()) {
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
	d.pktsSrc = d.pktsSrc[:last]
}

func (d *Decoder) removeCodNoOrder(ind int) {
	// https://stackoverflow.com/a/37335777
	last := len(d.pktsCod) - 1
	if ind != last {
		d.pktsCod[ind] = d.pktsCod[last]
	}
	d.pktsCod[last] = nil // prevent memory leaks
	d.pktsCod = d.pktsCod[:last]
}

// srcAvblUpdate adds packet ID of new SRC to srcAvbl, an ordered list of SRC available in the system.
// Obsolete elements are removed from srcAvbl in srcMissUpdate, which builds the list of missing SRC,
// used in recovery.
func (d *Decoder) srcAvblUpdate(id uint8) (repeatedSrc bool) {
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
	if !d.doCheckMissingSrc {
		return
	}
	d.doCheckMissingSrc = false // becomes true after d.lastSeenPkt update by new COD
	defer func() { rLogger.Debugf("Decoder MissingSrcPkts:%d", d.srcMiss) }()

	// Remove obsolete pkt ids from srcAvbl list
	if d.isObsoletePktId(d.srcAvbl[0]) {
		for i := 1; i < len(d.srcAvbl); i++ {
			if !d.isObsoletePktId(d.srcAvbl[i]) {
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

	// Check if there is any SRC available
	srcAvblLen := len(d.srcAvbl)
	if srcAvblLen == 0 {
		for i, missId := 0, d.obsoleteXhold; i < srcMissLen; i++ {
			d.srcMiss[i] = missId
			missId++
		}
		return
	}

	// Check which expected SRC IDs haven't been received
	var indAv, indMiss int
	for missId := d.obsoleteXhold; idLolderR(missId, maxId); missId++ {
		if d.srcAvbl[indAv] == missId {
			indAv++
			if indAv == srcAvblLen {
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
