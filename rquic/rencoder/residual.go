package rencoder

//package main

import (
	//"fmt"
	"sync"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type residualLoss struct {
	mu          sync.Mutex
	dlvdBff     []uint32
	lostBff     []uint32
	lastLossInd int
	cumLoss     float64
	numPeriods  int
	numPeriodsF float64
	threshold   float64
}

func (r *residualLoss) update(dlvd, lost uint32) { // meas. thread
	var oldL, newL float64
	r.mu.Lock()
	prevInd := r.lastLossInd
	r.lastLossInd = (r.lastLossInd + 1) % r.numPeriods

	// If there are more losses than deliveries,
	// these losses must be from previous period
	if lost >= dlvd {
		if updatedLost := r.lostBff[prevInd] + lost; updatedLost < r.dlvdBff[prevInd] {
			oldL = r.localLoss(prevInd)
			r.lostBff[prevInd] = updatedLost
			lost = 0
			newL = r.localLoss(prevInd)
			r.cumLoss += newL - oldL
			rLogger.Logf("Encoder Ratio ResidualLoss PrevPeriodLossUpdate Old:%f New:%f Avg:%f",
				oldL, newL, r.cumLoss / r.numPeriodsF,
			)
		} else {
			// There has been more losses in the previous periods, hard to guess where.
			// Store threshold as new local loss.
			dlvd = uint32(float64(lost) * (1/r.threshold - 1))
			rLogger.Logf("Encoder Ratio ResidualLoss PrevPeriodLossUpdate New:ResidualThreshold")
		}
	}

	// Update
	oldL = r.localLoss(r.lastLossInd)
	r.dlvdBff[r.lastLossInd] = dlvd
	r.lostBff[r.lastLossInd] = lost
	newL = r.localLoss(r.lastLossInd)
	r.cumLoss += newL - oldL

	rLogger.Logf("Encoder Ratio ResidualLoss New:%f Avg:%f", newL, r.cumLoss / r.numPeriodsF)
	r.mu.Unlock()
}

func (r *residualLoss) localLoss(i int) float64 {
	//i = (i % r.numPeriods + r.numPeriods) % r.numPeriods
	if r.lostBff[i] == 0 {
		return 0
	}
	return float64(r.lostBff[i]) / float64(r.dlvdBff[i] - r.lostBff[i])
}

func (r *residualLoss) LossValue() float64 { // meas. thread
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cumLoss / r.numPeriodsF
}

func (r *residualLoss) AboveThreshold() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cumLoss / r.numPeriodsF > r.threshold
}

func (r *residualLoss) reset() { // executed only when when meas. thread is starting
	r.mu.Lock()
	r.cumLoss = 0
	for i := 0; i < r.numPeriods; i++ {
		r.dlvdBff[i] = 0
		r.lostBff[i] = 0
	}
	r.mu.Unlock()
}

func (r *residualLoss) ChangeNumPeriods(newNum int) { // may actually interfere with meas. thread
	r.mu.Lock()
	defer r.mu.Unlock()

	if newNum == r.numPeriods {
		return
	}

	next := r.lastLossInd + 1

	if numDif := newNum - r.numPeriods; numDif > 0 {
		r.dlvdBff = append(r.dlvdBff[:next], append(make([]uint32, numDif), r.dlvdBff[next:]...)...)
		r.lostBff = append(r.lostBff[:next], append(make([]uint32, numDif), r.lostBff[next:]...)...)
		r.numPeriods = newNum
		r.numPeriodsF = float64(newNum)
		return
	}

	//if newNum < r.numPeriods {
	nextValid := (r.lastLossInd + r.numPeriods - newNum + 1) % r.numPeriods

	// update r.cumLoss
	if newNum > r.numPeriods/2 {
		for i := next; i != nextValid; i = (i + 1) % r.numPeriods {
			r.cumLoss -= r.localLoss(i)
		}
	} else { // if there is too much to subtract, sum what remains
		r.cumLoss = 0
		for i := nextValid; i != next; i = (i + 1) % r.numPeriods {
			r.cumLoss += r.localLoss(i)
		}
	}

	// remove oldest elements
	if nextValid > r.lastLossInd {
		r.dlvdBff = append(r.dlvdBff[:next], r.dlvdBff[nextValid:]...)
		r.lostBff = append(r.lostBff[:next], r.lostBff[nextValid:]...)
	} else {
		r.dlvdBff = r.dlvdBff[nextValid:next]
		r.lostBff = r.lostBff[nextValid:next]
	}

	// update r.lastLossInd if necessary
	if nextValid < next {
		if 0 < nextValid {
			r.lastLossInd -= nextValid
		}
	}

	r.numPeriods = newNum
	r.numPeriodsF = float64(newNum)
	//}
}

func makeResidualLoss(num int, threshold float64) *residualLoss {
	return &residualLoss{
		numPeriods:  num,
		numPeriodsF: float64(num),
		dlvdBff:     make([]uint32, num),
		lostBff:     make([]uint32, num),
		lastLossInd: 0,
		cumLoss:     0,
		threshold:   threshold,
	}
}

/* residualLoss
func main() {
	echo := fmt.Println

	rl := makeResidualLoss(4)

	rl.UpdateLoss(2) // 2
	rl.UpdateLoss(3) // 2.5
	rl.UpdateLoss(4) // 3
	rl.UpdateLoss(5) // 3.5
	//echo(rl.GetResidualLoss())

	rl.UpdateLoss(6) // 4.5
	rl.UpdateLoss(7) // 5.5
	//echo(rl.GetResidualLoss())

	rl.ChangeNum(2)   // 6.5
	rl.UpdateLoss(13) // 10
	//echo(rl.GetResidualLoss())

	rl.ChangeNum(5) // 4
	//echo(rl.GetResidualLoss())

	rl.UpdateLoss(10) // 6
	rl.UpdateLoss(3)  // 6.6
	rl.UpdateLoss(7)  // 8
	rl.UpdateLoss(4)  // 7.4
	rl.UpdateLoss(6)  // 6
	rl.UpdateLoss(10) // 6
	//echo(rl.GetResidualLoss())

	//echo(rl.losses, rl.lastLossInd)
	rl.ChangeNum(4) // 6.75
	//echo(rl.losses, rl.lastLossInd)
	//echo(rl.GetResidualLoss())

	rl.ChangeNum(8) // 3.375
	//echo(rl.losses, rl.lastLossInd)
	//echo(rl.GetResidualLoss())

	rl.UpdateLoss(0)   // 3.375
	rl.UpdateLoss(0)   // 3.375
	rl.UpdateLoss(0)   // 3.375
	rl.UpdateLoss(1.5) // 3.5625
	echo(rl.losses, rl.lastLossInd)
	//echo(rl.GetResidualLoss())
	rl.ChangeNum(4) // 0.375
	echo(rl.losses, rl.lastLossInd)
	echo(rl.GetResidualLoss())
}
*/
