package rdecoder

import (
	"github.com/lucas-clemente/quic-go/rquic"
)

func (d *Decoder) lenNotProtected() int { return *d.lenDCID + rquic.SrcHeaderSize }
func (d *Decoder) rQuicHdrPos() int     { return 1 /*1st byte*/ + *d.lenDCID }
func (d *Decoder) rQuicSrcPldPos() int  { return 1 /*1st byte*/ + *d.lenDCID + rquic.SrcHeaderSize }

func idLolderR(older, newer uint8) bool {
	return (newer - older) > 128
}

func (d *Decoder) isObsolete(id uint8) bool {
	return (d.obsoleteXhold - id) > 128
}

func (d *Decoder) parseSrc(raw []byte) []byte {
	lng := len(raw) - d.lenNotProtected()
	pldHdr := make([]byte, 3)
	pldHdr[0] = byte(lng / 256)
	pldHdr[1] = byte(lng % 256)
	pldHdr[2] = raw[0] // 1st byte, which is partially encrypted
	return append(pldHdr, raw[d.rQuicSrcPldPos():]...)
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

func (d *Decoder) updateObsoleteXhold(cod *parsedCod) {
	// https://tools.ietf.org/html/draft-ietf-quic-recovery-24#appendix-B.1
	//     kLossReductionFactor:  Reduction in congestion window when a new loss
	//        event is detected.  The RECOMMENDED value is 0.5.
	// genSize <= CWND  ==>  prevCOD.genSize <= 2 * COD.genSize
	// oldest valid ID: COD.Id - COD.genSize - 2*COD.genSize
	codId := cod.lastId()
	d.obsoleteXhold = codId - uint8(cod.remaining*3) // when this method is called,
	d.nwstCodId = codId                              // cod.remaining == genSize
	d.doCheckMissingSrc = true
}

func (d *Decoder) srcAvblUpdate(id uint8) (repeatedSrc bool) {
	// d.isObsolete(id) == true is meant to be done outside
	for i := len(d.srcAvbl) - 1; i >= 0; i-- {
		if idLolderR(d.srcAvbl[i], id) {
			d.srcAvbl = append(append(d.srcAvbl[:i+1], id), d.srcAvbl[i+1:]...)
			return
		}
		if d.srcAvbl[i] == id { // pkt already rx-d
			repeatedSrc = true
			return
		}
	}
	// At this point, id must be the oldest id in the list
	d.srcAvbl = append([]uint8{id}, d.srcAvbl...)
	return
}

func (d *Decoder) srcMissUpdate() {
	// If multiple redun-s per gen., do not repeat this action.
	d.doCheckMissingSrc = false // becomes true after nwstCodId update
	// Remove obsolete pkt ids from srcAvbl list
	if d.isObsolete(d.srcAvbl[0]) {
		for i := 1; i < len(d.srcAvbl); i++ {
			if !d.isObsolete(d.srcAvbl[i]) {
				d.srcAvbl = d.srcAvbl[i:]
				break
			}
		}
	}
	// Check which expected SRC IDs haven't been received
	indAv := 0
	indMiss := 0
	maxId := d.nwstCodId + 1
	d.srcMiss = make([]uint8, int(maxId-d.obsoleteXhold) /*expected SRC*/ -len(d.srcAvbl))
	// Building srcMiss starting from d.obsoleteXhold at the beginning
	// will result in d.Recover() trying to recover packets that do not
	// exist yet. For longer communications
	for missId := d.obsoleteXhold; idLolderR(missId, maxId); missId++ {
		if d.srcAvbl[indAv] == missId {
			indAv++
			if indAv == len(d.srcAvbl) {
				for indMiss < len(d.srcMiss) {
					missId++
					d.srcMiss[indMiss] = missId
					indMiss++
				}
				return
			}
		} else {
			d.srcMiss[indMiss] = missId
			indMiss++
			if indMiss == len(d.srcMiss) {
				return
			}
		}
	}
}
