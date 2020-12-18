package rdecoder

import (
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

func (d *Decoder) offset() int { return 1 /*1st byte*/ + d.lenDCID }

func (d *Decoder) isObsoletePktId(p uint8) bool {
	// p == d.obsoleteXhold --> p is still valid
	return rquic.IdLeftOlderRight(p, d.obsoleteXhold)
}

func (d *Decoder) isObsoleteGenId(g uint8) bool {
	// g == d.lastValidGen --> g is still valid
	return rquic.IdLeftOlderRight(g, d.lastValidGen)
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
		if newXhold := p + 1; rquic.IdLeftOlderRight(d.obsoleteXhold, newXhold) {
			d.writeNewXhold(newXhold)
		}
		return true
	}
	return false
}

func (d *Decoder) maybeUpdateXhold() {
	if newXhold := d.lastSeenPkt - d.distToLastValidId; rquic.IdLeftOlderRight(d.obsoleteXhold, newXhold) {
		d.writeNewXhold(newXhold)
	}
}

func (d *Decoder) writeNewXhold(newXhold uint8) {
	d.obsoleteXhold = newXhold

	// Clean srcMiss list
	if len(d.srcMiss) == 0 {
		return
	}
	if rquic.IdLeftOlderEqRight(d.obsoleteXhold, d.srcMiss[0]) {
		return
	}
	for i, m := range d.srcMiss {
		if rquic.IdLeftOlderRight(d.obsoleteXhold, m) {
			d.srcMiss = d.srcMiss[i:]
			return
		}
	}
}

func (d *Decoder) maybeCheckObsoleteSrc() {
	if int(d.lastSeenPkt - d.obsoleteXhold) < len(d.pktsSrc) {
		return
	}
	for i := 0; i < len(d.pktsSrc); i++ {
		if moreSrc := d.handleObsoleteSrc(i); !moreSrc {
			return
		}
	}
}

// lastSeen updates lastSeenPkt and lastSeenGen
func (d *Decoder) lastSeen(p, g byte) bool {
	if rquic.IdLeftOlderRight(d.lastSeenPkt, p) {
		d.lastSeenPkt = p
		if rquic.IdLeftOlderRight(d.lastSeenGen, g) {
			d.lastSeenGen = g
			// Any packet belongs to [overlap] generations. Last [overlap] + Margin generations are valid.
			lvg := d.lastValidGen
			d.lastValidGen = d.lastSeenGen - d.lastSeenOverlap - rquic.GenMargin + 1
			rLogger.Debugf("Decoder Updating lastValidGen Old:%d New:%d", lvg, d.lastValidGen)
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
	if ind < d.obsoleteCodCheckedInd {
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

func (d *Decoder) alreadyReceived(id uint8) bool {
	expected := d.lastSeenSrc + 1

	// New SRC
	if rquic.IdLeftOlderEqRight(expected, id) {
		for ; expected != id; expected++ {
			d.srcMiss = append(d.srcMiss, expected)
		}
		d.lastSeenSrc = id
		return false
	}

	// Recovered or out of order SRC
	for i := len(d.srcMiss) - 1; i >= 0; i-- {
		if d.srcMiss[i] == id {
			d.srcMiss = append(d.srcMiss[:i], d.srcMiss[i+1:]...)
			return false
		}
	}

	// id not in srcMiss => already received
	return true
}
