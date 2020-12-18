package rencoder

//package main

import (
	//"fmt"
	"sync"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type residualLoss struct {
	mu          sync.Mutex
	losses      []float64
	lastLossInd int
	cumLoss     float64
	numPeriods  int
	numPeriodsF float64
}

func (r *residualLoss) update(newLoss float64) float64 { // meas. thread
	r.mu.Lock()
	r.lastLossInd = (r.lastLossInd + 1) % r.numPeriods
	r.cumLoss += newLoss - r.losses[r.lastLossInd]
	r.losses[r.lastLossInd] = newLoss
	lossValue := r.cumLoss / r.numPeriodsF
	r.mu.Unlock()
	rLogger.Logf("Encoder Ratio ResidualLoss New:%f Avg:%f", newLoss, lossValue)
	return lossValue
}

func (r *residualLoss) LossValue() float64 { // meas. thread
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cumLoss / r.numPeriodsF
}

func (r *residualLoss) reset() { // executed only when when meas. thread is starting
	r.mu.Lock()
	r.cumLoss = 0
	for i := range r.losses {
		r.losses[i] = 0
	}
	r.mu.Unlock()
}

func (r *residualLoss) ChangeNumPeriods(newNum int) { // may actally interfere with meas. thread
	r.mu.Lock()
	defer r.mu.Unlock()

	if newNum == r.numPeriods {
		return
	}

	next := r.lastLossInd + 1

	if numDif := newNum - r.numPeriods; numDif > 0 {
		r.losses = append(r.losses[:next], append(make([]float64, numDif), r.losses[next:]...)...)
		r.numPeriods = newNum
		r.numPeriodsF = float64(newNum)
		return
	}

	//if newNum < r.numPeriods {
	nextValid := (r.lastLossInd + r.numPeriods - newNum + 1) % r.numPeriods

	// update r.cumLoss
	if newNum > r.numPeriods/2 {
		for i := next; i != nextValid; i = (i + 1) % r.numPeriods {
			r.cumLoss -= r.losses[i]
		}
	} else { // if there is too much to subtract, sum what remains
		r.cumLoss = 0
		for i := nextValid; i != next; i = (i + 1) % r.numPeriods {
			r.cumLoss += r.losses[i]
		}
	}

	// remove oldest elements from r.losses
	if nextValid > r.lastLossInd {
		r.losses = append(r.losses[:next], r.losses[nextValid:]...)
	} else {
		r.losses = r.losses[nextValid:next]
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

func makeResidualLoss(num int) *residualLoss {
	return &residualLoss{
		numPeriods:  num,
		numPeriodsF: float64(num),
		losses:      make([]float64, num),
		lastLossInd: 0,
		cumLoss:     0,
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
