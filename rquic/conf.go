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
		c.CodingConf = GetCConfDefault()
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
		c.Scheme = DefaultScheme
	}
	if c.Overlap == 0 {
		c.Overlap = DefaultOverlap
	}
	if c.Reduns == 0 {
		c.Reduns = DefaultReduns
	}
	if c.RatioVal == 0 {
		c.RatioVal = DefaultRatioVal
	}
	if c.Dynamic == 0 {
		c.Dynamic = DefaultDynamic
	}
	if c.TPeriod.String() == new(time.Duration).String() {
		c.TPeriod = DefaultTPeriod
	}
	if c.NumPeriods == 0 {
		c.NumPeriods = DefaultNumPeriods
	}
	if c.GammaTarget == 0 {
		c.GammaTarget = DefaultGammaTarget
	}
	if c.DeltaRatio == 0 {
		c.DeltaRatio = DefaultDeltaRatio
	}
}

//-------------------------------------- CConf templates

// Globecom 2019 values
const (
	Globecom2019Scheme           = SchemeXor
	Globecom2019Overlap  int     = 1
	Globecom2019Reduns   int     = 1
	Globecom2019RatioVal float64 = 10
	Globecom2019Dynamic  int     = 1
	// TPeriod := 3 * RTT <-- 10.1109/GLOBECOM38437.2019.9013401
	// rQUIC can take SRTT and multply it by 3.
	// For tests in controlled testbeds, TPeriod can be specified directly.
	Globecom2019TPeriod         = 3 * 25 * time.Millisecond
	Globecom2019NumPeriods  int = 3
	Globecom2019GammaTarget     = 0.01
	Globecom2019DeltaRatio      = 0.33
)

// Default values
const (
	DefaultScheme      = Globecom2019Scheme
	DefaultOverlap     = Globecom2019Overlap
	DefaultReduns      = Globecom2019Reduns
	DefaultRatioVal    = Globecom2019RatioVal
	DefaultDynamic     = Globecom2019Dynamic
	DefaultTPeriod     = Globecom2019TPeriod
	DefaultNumPeriods  = Globecom2019NumPeriods
	DefaultGammaTarget = Globecom2019GammaTarget
	DefaultDeltaRatio  = Globecom2019DeltaRatio
)

func GetCConfGlobecom2019() *CConf {
	return &CConf{
		Scheme:      Globecom2019Scheme,
		Overlap:     Globecom2019Overlap,
		Reduns:      Globecom2019Reduns,
		RatioVal:    Globecom2019RatioVal,
		Dynamic:     Globecom2019Dynamic,
		TPeriod:     Globecom2019TPeriod,
		NumPeriods:  Globecom2019NumPeriods,
		GammaTarget: Globecom2019GammaTarget,
		DeltaRatio:  Globecom2019DeltaRatio,
	}
}

func GetCConfDefault() *CConf {
	return &CConf{
		Scheme:      DefaultScheme,
		Overlap:     DefaultOverlap,
		Reduns:      DefaultReduns,
		RatioVal:    DefaultRatioVal,
		Dynamic:     DefaultDynamic,
		TPeriod:     DefaultTPeriod,
		NumPeriods:  DefaultNumPeriods,
		GammaTarget: DefaultGammaTarget,
		DeltaRatio:  DefaultDeltaRatio,
	}
}

//-------------------------------------- Conf templates

func GetConf(c *CConf) *Conf {
	if c == nil {
		c = GetCConfDefault()
	}
	return &Conf{
		EnableEncoder: true,
		EnableDecoder: true,
		CodingConf:    c,
	}
}

func GetConfTx(c *CConf) *Conf {
	if c == nil {
		c = GetCConfDefault()
	}
	return &Conf{
		EnableEncoder: true,
		EnableDecoder: false,
		CodingConf:    c,
	}
}

func GetConfRx(c *CConf) *Conf {
	if c == nil {
		c = GetCConfDefault()
	}
	return &Conf{
		EnableEncoder: false,
		EnableDecoder: true,
		CodingConf:    c,
	}
}
