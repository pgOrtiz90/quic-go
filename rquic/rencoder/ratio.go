package rencoder

import {
    "time"
    "sync"
}



type ratio struct {
    ratioMu         sync.RWMutex
    ratio           float64
    
    dynamic         bool
    MeasPeriod      time.Duration
    residual        *residualLoss
    residualTarget  float64
    ratioDelta      float64
    stopMeas        chan struct{}
    stopMeasDone    chan struct{}
    
    rtxMu           sync.Mutex
    rtx             uint32
    txMu            sync.Mutex
    tx              uint32
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
}

func (r *ratio) MakeStatic() {
    if r.dynamic {
        close(r.stopMeas)
        <- r.stopMeasDone
        r.dynamic = false
    }
}

func (r *ratio) MakeDynamic() {
    if !r.dynamic {
        r.stopMeas        = make(chan struct{}, 0)
        r.stopMeasStopped = make(chan struct{}, 0)
        go r.measureLoss()
        r.dynamic = true
    }
}

func (r *ratio) AddReTxCount() {
	r.rtxMu.Lock()
    r.rtx++
	r.rtxMu.Unlock()
}

func (r *ratio) AddTxCount() {
	r.txMu.Lock()
    r.tx++
	r.txMu.Unlock()
}

func (r *ratio) measureLoss() { // meas. thread
    
    r.residual.reset()
    
    r.rtxMu.Lock()
    r.rtx = 0
    r.rtxMu.Unlock()
    
    r.txMu.Lock()
    r.tx = 0
    r.txMu.Unlock()
    
    for {
        select {
        case: <- r.stopMeas:
            close(r.stopMeasStopped)
            return
        default:
            
            timer := time.NewTimer(r.MeasPeriod)
            <- timer.C
            
            r.rtxMu.Lock()
            rtx := r.rtx
            r.rtx = 0
            r.rtxMu.Unlock()
            
            r.txMu.Lock()
            tx := r.tx
            r.tx = 0
            r.txMu.Unlock()
            
            r.residual.update(float64(rtx)/float64(tx - rtx))
            r.update()
        }
    }
}

func (r *ratio) update() { // meas. thread
    
    ratio := r.Check()
    
    if r.residual.LossValue() > r.residualTarget {
        ratio *= 1 - r.ratioDelta
    } else {
        ratio *= 1 + r.ratioDelta
    } // TODO: MAYBE change gamma, delta, T & N on-the-fly (will need more mutexes)

    if ratio < rquic.MinRatio {ratio = rquic.MinRatio}
	if ratio >            255 {ratio =            255}
    
    r.Change(ratio)
    
    // TODO: imlement or reuse traces
    //traces.PrintFecEncoder(d.encoder.Ratio)
	//fmt.Printf("Update Ratio Old: %d, New: %f, residual: %f, Target: %f N: %d\n", d.encoder.Ratio, d.Ratio, residual, d.target,d.N)
}

func makeRatio (
    dynamic         bool,
    Tperiod         time.Period,
    numPeriods      int,
    gammaTarget     float64,
    deltaRatio      uint8,
) *ratio {
    r := &Ratio {
        MeasPeriod      : Tperiod,
        residual        : makeResidualLoss(numPeriods),
        residualTarget  : gammaTarget,
        ratioDelta      : deltaRatio,
    }
    if dynamic {r.MakeDynamic()}
    return dr
}
