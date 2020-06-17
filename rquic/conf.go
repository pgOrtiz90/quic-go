package rquic

import (
	"time"
)

type Conf struct {
	EnableEncoder bool
	EnableDecoder bool
	CodingConf    *CConf
}

func (c *Conf) Populate() {
	if !c.EnableEncoder {
		return
	}
	if c.CodingConf == nil {
		newCConf := CConfDefault
		c.CodingConf = &newCConf
		return
	}
	c.CodingConf.Populate()
}

type CConf struct {
	Scheme      uint8
	Overlap     int
	Reduns      int
	RatioVal    float64
	Dynamic     int // 1: dynamic; 0: default; -1: static
	TPeriod     time.Duration
	NumPeriods  int
	GammaTarget float64
	DeltaRatio  float64
}

func (c *CConf) Populate() {
	if c.Scheme == 0 {
		c.Scheme = CConfDefault.Scheme
	}
	if c.Overlap == 0 {
		c.Overlap = CConfDefault.Overlap
	}
	if c.Reduns == 0 {
		c.Reduns = CConfDefault.Reduns
	}
	if c.RatioVal == 0 {
		c.RatioVal = CConfDefault.RatioVal
	}
	if c.Dynamic == 0 {
		c.Dynamic = CConfDefault.Dynamic
	}
	if c.TPeriod.String() == new(time.Duration).String() {
		c.TPeriod = CConfDefault.TPeriod
	}
	if c.NumPeriods == 0 {
		c.NumPeriods = CConfDefault.NumPeriods
	}
	if c.GammaTarget == 0 {
		c.GammaTarget = CConfDefault.GammaTarget
	}
	if c.DeltaRatio == 0 {
		c.DeltaRatio = CConfDefault.DeltaRatio
	}
}

//-------------------------------------- CConf templates

var CConfGlobecom2019 CConf = CConf{
	Scheme:   SchemeXor,
	Overlap:  1,
	Reduns:   1,
	RatioVal: 10,
	Dynamic:  1,
	// TPeriod := 3 * RTT <-- 10.1109/GLOBECOM38437.2019.9013401
	// rQUIC can take SRTT and multply it by 3.
	// For tests in controlled testbeds, TPeriod can be specified directly.
	TPeriod:     time.Duration(3 * 25 * time.Millisecond),
	NumPeriods:  3,
	GammaTarget: 0.01,
	DeltaRatio:  0.33,
}

var CConfDefault CConf = CConf{
	Scheme:      CConfGlobecom2019.Scheme,
	Overlap:     CConfGlobecom2019.Overlap,
	Reduns:      CConfGlobecom2019.Reduns,
	RatioVal:    CConfGlobecom2019.RatioVal,
	Dynamic:     CConfGlobecom2019.Dynamic,
	TPeriod:     CConfGlobecom2019.TPeriod,
	NumPeriods:  CConfGlobecom2019.NumPeriods,
	GammaTarget: CConfGlobecom2019.GammaTarget,
	DeltaRatio:  CConfGlobecom2019.DeltaRatio,
}

//-------------------------------------- Conf templates

var ConfDefault Conf = Conf{
	EnableEncoder: true,
	EnableDecoder: true,
	CodingConf:    &CConfDefault,
}

var ConfTx Conf = Conf{
	EnableEncoder: true,
	EnableDecoder: false,
	CodingConf:    &CConfDefault,
}

var ConfRx Conf = Conf{
	EnableEncoder: false,
	EnableDecoder: true,
	CodingConf:    &CConfDefault,
}
