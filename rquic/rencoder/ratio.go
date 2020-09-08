package rencoder

import (
	"time"
	"sync"

	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

type DynRatio interface {
	Check() float64
	Change(float64)
	IsDynamic() bool
	MakeStatic()
	MakeDynamic()
	AddTxCount()
	UpdateUnAcked(int, int)
}

type ratio struct {
	ratioMu sync.RWMutex
	ratio   float64

	dynamic        bool
	MeasPeriod     time.Duration
	timer          *time.Timer
	residual       *residualLoss
	ratioDecrease  float64
	ratioIncrease  float64
	stopMeas       chan struct{}
	stopMeasDone   chan struct{}

	unAckedMu sync.Mutex
	lost      uint32
	unAcked   uint32
	txMu      sync.Mutex
	tx        uint32
}

func (r *ratio) Check() float64 {
	r.ratioMu.RLock()
	defer r.ratioMu.RUnlock()
	return r.ratio
}

func (r *ratio) Change(newR float64) {
	r.ratioMu.Lock()
	r.ratio = newR
	r.ratioMu.Unlock()
	rLogger.Logf("Encoder Ratio NewValue:%f", newR)
}

func (r *ratio) IsDynamic() bool {
	return r.dynamic
}

func (r *ratio) MakeStatic() {
	was := r.dynamic
	if r.dynamic {
		close(r.stopMeas)
		<-r.stopMeasDone
		r.dynamic = false
	}
	rLogger.Logf("Encoder Ratio WasDynamic:%t IsNowDynamic:%t", was, r.dynamic)
}

func (r *ratio) MakeDynamic() {
	was := r.dynamic
	if !r.dynamic {
		r.stopMeas = make(chan struct{}, 0)
		r.stopMeasDone = make(chan struct{}, 0)
		go r.measureLoss()
		r.dynamic = true
	}
	rLogger.Logf("Encoder Ratio WasDynamic:%t IsNowDynamic:%t", was, r.dynamic)
}

func (r *ratio) UpdateUnAcked(lost, unAcked int) {
	if !r.dynamic {
		return
	}
	r.unAckedMu.Lock()
	r.lost += uint32(lost)
	r.unAcked = uint32(unAcked)
	r.unAckedMu.Unlock()
	rLogger.Debugf("Encoder Ratio ProcessedACK Lost:%d UnACKed:%d", lost, unAcked)
}

func (r *ratio) AddTxCount() {
	if !r.dynamic {
		return
	}
	r.txMu.Lock()
	r.tx++
	r.txMu.Unlock()
}

func (r *ratio) measureLoss() { // meas. thread
	var tx, lost, unAcked uint32

	r.residual.reset()

	r.unAckedMu.Lock()
	r.lost = 0
	r.unAcked = 0
	r.unAckedMu.Unlock()

	r.txMu.Lock()
	r.tx = 0
	r.txMu.Unlock()

	r.timer = time.NewTimer(r.MeasPeriod)

	for {
		select {
		case <-r.stopMeas:
			close(r.stopMeasDone)
			return
		case <-r.timer.C:

			r.unAckedMu.Lock()
			lost = r.lost
			r.lost = 0
			unAcked = r.unAcked
			r.unAckedMu.Unlock()

			r.txMu.Lock()
			tx = r.tx
			r.tx = 0
			r.txMu.Unlock()

			if tx > 0 || unAcked > 0 || lost > 0 {
				rLogger.Logf("Encoder Ratio Update Tx:%d Lost:%d UnAcked:%d", tx, lost, unAcked)
				// UnACKed packets have been delivered? No idea, subtract them from the transmitted ones.
				tx -= unAcked // original rQUIC does not subtract
				r.residual.update(tx, lost)
				r.update()
			}

			r.timer = time.NewTimer(r.MeasPeriod)
		}
	}
}

func (r *ratio) update() { // meas. thread

	ratio := r.Check()

	if r.residual.AboveThreshold() {
		ratio *= r.ratioDecrease
	} else {
		ratio *= r.ratioIncrease
	} // TODO: MAYBE change gamma, delta, T & N on-the-fly (will need more mutexes)

	if ratio < rquic.MinRatio {
		ratio = rquic.MinRatio
	} else if ratio > rquic.MaxRatio {
		ratio = rquic.MaxRatio
	}

	r.Change(ratio)
}

func MakeRatio(
	ratioVal    float64,
	dynamic     bool,
	Tperiod     time.Duration,
	numPeriods  int,
	gammaTarget float64,
	deltaRatio  float64,
) *ratio {
	rLogger.Logf("Encoder Ratio Config Dynamic:%t TMeasPeriod:%s NumPeriods:%d GammaTarget:%f DeltaRatio:%f",
		dynamic, Tperiod.String(), numPeriods, gammaTarget, deltaRatio,
	)
	r := &ratio{
		ratio:          ratioVal,
		MeasPeriod:     Tperiod,
		residual:       makeResidualLoss(numPeriods, gammaTarget),
		ratioDecrease:  1-deltaRatio,
		ratioIncrease:  1+deltaRatio,
	}
	if dynamic {
		r.MakeDynamic()
	}
	return r
}
