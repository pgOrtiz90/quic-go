package rencoder

import (
	"time"
	"sync"

	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type DynRatio struct {
	ratioMu sync.RWMutex
	ratio   float64

	dynamic        bool
	MeasPeriod     time.Duration
	timer          *time.Timer
	residual       *smoothedValue
	residualTarget float64
	residualOff    float64
	ratioDecrease  float64
	ratioIncrease  float64
	stopMeas       chan struct{}
	stopMeasDone   chan struct{}

	ackStatsMu sync.Mutex
	lost       int
	unAcked    int // TODO: Maybe remove. Used only for logging.
	tx         int
}

func (r *DynRatio) Check() float64 {
	r.ratioMu.RLock()
	defer r.ratioMu.RUnlock()
	return r.ratio
}

func (r *DynRatio) Change(newR float64) {
	// Keep ratio in its bounds
	if newR < rquic.MinRatio {
		newR = rquic.MinRatio
	} else if newR > rquic.MaxRatio {
		newR = rquic.MaxRatio
	}
	r.ratioMu.Lock()
	oldR := r.ratio
	r.ratio = newR
	r.ratioMu.Unlock()

	if oldR == newR {
		return
	}

	rLogger.Trace("", oldR) // for a more fair and easier representation of ratio evolution.
	rLogger.Trace("", newR)
	rLogger.Logf("Encoder Ratio NewValue:%f", newR)
}

func (r *DynRatio) ResLossAppreciable() bool {
	return r.residual.Value() > r.residualOff
}

func (r *DynRatio) IsDynamic() bool {
	return r.dynamic
}

func (r *DynRatio) MakeStatic() {
	was := r.dynamic
	if r.dynamic {
		close(r.stopMeas)
		<-r.stopMeasDone
		r.dynamic = false
	}
	rLogger.Logf("Encoder Ratio WasDynamic:%t IsNowDynamic:%t", was, r.dynamic)
}

func (r *DynRatio) MakeDynamic() {
	was := r.dynamic
	if !r.dynamic {
		r.stopMeas = make(chan struct{}, 0)
		r.stopMeasDone = make(chan struct{}, 0)
		go r.measureLoss()
		r.dynamic = true
	}
	rLogger.Logf("Encoder Ratio WasDynamic:%t IsNowDynamic:%t", was, r.dynamic)
}

func (r *DynRatio) AckStatsUpdate(lost, delivered, unAcked int) {
	if !r.dynamic {
		return
	}

	r.ackStatsMu.Lock()
	r.lost += lost
	r.unAcked = unAcked
	r.tx += delivered
	r.ackStatsMu.Unlock()

	rLogger.Debugf("Encoder Ratio ProcessedACK Lost:%d Delivered:%d UnACKed:%d", lost, delivered, unAcked)
}

func (r *DynRatio) measureLoss() { // meas. thread
	var tx, lost, unAcked int

	r.residual.Reset()

	r.ackStatsMu.Lock()
	r.lost = 0
	r.unAcked = 0
	r.tx = 0
	r.ackStatsMu.Unlock()

	r.timer = time.NewTimer(r.MeasPeriod)

	for {
		select {
		case <-r.stopMeas:
			close(r.stopMeasDone)
			return
		case <-r.timer.C:
			// Read ACK information
			r.ackStatsMu.Lock()
			lost = r.lost
			r.lost = 0
			unAcked = r.unAcked
			tx = r.tx
			r.tx = 0
			r.ackStatsMu.Unlock()
			rLogger.Logf("Encoder Ratio Update Tx:%d Lost:%d UnAcked:%d", tx, lost, unAcked)
			rLogger.MaybeIncreaseRxLstN(lost)

			// Check inconsistent measurements
			if tx < lost || tx == 0 {
				// tx < lost > 0 --> Inconsistent measurement. Sign of a dying connection.
				// tx == 0 --> Nothing transmitted? Pause ratio update.
				rLogger.Logf("Encoder Ratio NoUpdate")
				r.timer = time.NewTimer(r.MeasPeriod)
				continue
			}
			// At this point, 0 < tx >= lost

			// Update residual loss
			newLoss := float64(lost) / float64(tx)
			lossValue := r.residual.Update(newLoss)
			rLogger.Logf("Encoder Ratio ResidualLoss New:%f Avg:%f", newLoss, lossValue)
			r.update(lossValue > r.residualTarget)

			r.timer = time.NewTimer(r.MeasPeriod)
		}
	}
}

func (r *DynRatio) update(decrease bool) { // meas. thread
	r.ratioMu.Lock()
	defer r.ratioMu.Unlock()

	oldR := r.ratio
	if decrease {
		r.ratio *= r.ratioDecrease
		if r.ratio < rquic.MinRatio {
			r.ratio = rquic.MinRatio
		}
	} else {
		r.ratio *= r.ratioIncrease
		if r.ratio > rquic.MaxRatio {
			r.ratio = rquic.MaxRatio
		}
	}

	rLogger.Debugf("Encoder Ratio UpdatedValue:%f", r.ratio)
	if oldR == r.ratio {
		return
	}
	rLogger.Trace("", oldR) // for a more fair and easier representation of ratio evolution.
	rLogger.Trace("", r.ratio)
}

func MakeRatio(
	ratioVal    float64,
	dynamic     bool,
	Tperiod     time.Duration,
	numPeriods  int,
	gammaTarget float64,
	deltaRatio  float64,
) *DynRatio {
	rLogger.Logf("Encoder Ratio Config Dynamic:%t TMeasPeriod:%s NumPeriods:%d GammaTarget:%f DeltaRatio:%f",
		dynamic, Tperiod.String(), numPeriods, gammaTarget, deltaRatio,
	)
	r := &DynRatio{
		ratio:          ratioVal,
		MeasPeriod:     Tperiod,
		residual:       NewSmoothedValue(numPeriods),
		residualTarget: gammaTarget,
		residualOff:	gammaTarget * rquic.ResLossFactor,
		ratioDecrease:  1 - deltaRatio,
		ratioIncrease:  1 + deltaRatio,
	}
	if dynamic {
		r.MakeDynamic()
	}
	return r
}
