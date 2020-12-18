package rquic

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"io/ioutil"
	"strings"
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

func (c *Conf) String() string {
	msg, _ := json.Marshal(c)
	if c.CodingConf == nil {
		return string(msg)
	}
	oldS := fmt.Sprintf("\"Scheme\":%d", c.CodingConf.Scheme)
	newS := "\"Scheme\":\"" + SchemesExplainer[c.CodingConf.Scheme] + "\""
	return strings.Replace(string(msg), oldS, newS, 1)
}

const (
	ConfOverviewHeader = "Protocol,Scheme,op,r,Q,D,T,TN,G,d"
	ConfOverviewEmpty = ",,,,,,,,,"
)
func (c *Conf) Overview() string {
	if c.EnableEncoder {
		var ov string
		if c.EnableDecoder {
			ov = "rQUIC,"
		} else {
			ov = "rQUIC-Encoder,"
		}
		if c.CodingConf != nil {
			extra := strings.Replace(fmt.Sprintf("%v", c.CodingConf), " ", ",", -1)
			return ov + extra[2:len(extra)-1] // &{...} --> ...
		}
	} else {
		if c.EnableDecoder {
			return "rQUIC-Decoder" + ConfOverviewEmpty
		} else {
			return "QUIC" + ConfOverviewEmpty
		}
	}
	return ConfOverviewEmpty
}

func (c *Conf) WriteJson(file string) error {
	var ccj *CConfJson
	if c.EnableEncoder {
		cc := c.CodingConf
		ccj = &CConfJson{
			Scheme:      SchemesExplainer[cc.Scheme],
			Overlap:     float64(cc.Overlap),
			Reduns:      float64(cc.Reduns),
			RatioVal:    cc.RatioVal,
			Dynamic:     float64(cc.Dynamic),
			TPeriodMS:   float64(cc.TPeriod.Milliseconds()),
			NumPeriods:  float64(cc.NumPeriods),
			GammaTarget: cc.GammaTarget,
			DeltaRatio:  cc.DeltaRatio,
		}
	}
	cj := &ConfJson{
		EnableEncoder: c.EnableEncoder,
		EnableDecoder: c.EnableDecoder,
		CConfJson:     ccj,
	}
	return cj.WriteJson(file)
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

//-------------------------------------- (C)Conf and JSON

type ConfJson struct {
	EnableEncoder bool
	EnableDecoder bool
	CConfJson     *CConfJson
}

func (c *ConfJson) Complementary() *ConfJson {
	return &ConfJson{
		EnableEncoder: c.EnableDecoder,
		EnableDecoder: c.EnableEncoder,
		CConfJson:     c.CConfJson,
	}
}

func (c *ConfJson) Overview(long bool) (ov string) {
	if c.EnableEncoder {
		if c.EnableDecoder {
			ov = "F" // Full, encoder & decoder
		} else {
			ov = "E" // Encoder
		}
	} else {
		if c.EnableDecoder {
			return "D" // Decoder
		} else {
			return "0" // None
		}
	}
	if c.CConfJson == nil {
		return
	}

	var format string
	if long {
		format = "%+v"
	} else {
		format = "%v"
	}
	extra := strings.Replace(fmt.Sprintf(format, c.CConfJson), " ", "_", -1)
	return ov + "__" + extra[2:len(extra)-1] // &{...}
}

func (c *ConfJson) WriteJson(file string) error {
	var d *ConfJson
	if c.EnableEncoder {
		d = c
	} else {
		d = &ConfJson{EnableDecoder: c.EnableDecoder}
	}

	if m, err := json.Marshal(d); err != nil {
		return fmt.Errorf("failed to marshal json with Conf: %w", err)
	} else if err := ioutil.WriteFile(file, m, 0644); err != nil {
		return fmt.Errorf("failed to write json with Conf: %w", err)
	}
	return nil
}

func ReadConfFromJson(file string) (*Conf, error) {
	var raw []byte
	var err error
	var cc *CConf
	var cj = new(ConfJson)
	if raw, err = ioutil.ReadFile(file); err != nil {
		return &Conf{}, fmt.Errorf("failed to open %s: %w", file, err)
	}
	if err = json.Unmarshal(raw, cj); err != nil {
		return &Conf{}, fmt.Errorf("failed to import %s: %w", file, err)
	}
	if cj == nil {
		return &Conf{}, errors.New("empty CConf")
	}
	cc, err = fromCCJtoCC(cj.CConfJson)
	return &Conf{cj.EnableEncoder, cj.EnableDecoder, cc}, err
}

type CConfJson struct {
	Scheme      string
	Overlap     float64
	Reduns      float64
	RatioVal    float64
	Dynamic     float64 // 1: dynamic; 0: default; -1: static
	TPeriodMS   float64
	NumPeriods  float64
	GammaTarget float64
	DeltaRatio  float64
}

func fromCCJtoCC(cj *CConfJson) (*CConf, error) {
	if cj == nil {
		return nil, nil
	}
	var scheme uint8
	var ok bool
	if scheme, ok = SchemesReader[cj.Scheme]; !ok {
		return nil, errors.New("Scheme " + cj.Scheme + " not found")
	}
	return &CConf{
		Scheme:      scheme,
		Overlap:     int(cj.Overlap),
		Reduns:      int(cj.Reduns),
		RatioVal:    cj.RatioVal,
		Dynamic:     int(cj.Dynamic),
		TPeriod:     time.Duration(cj.TPeriodMS) * time.Millisecond,
		NumPeriods:  int(cj.NumPeriods),
		GammaTarget: cj.GammaTarget,
		DeltaRatio:  cj.DeltaRatio,
	}, nil
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

func GetConfTx(encodConf *CConf) *Conf {
	if encodConf == nil {
		encodConf = GetCConfDefault()
	}
	return &Conf{
		EnableEncoder: true,
		EnableDecoder: false,
		CodingConf:    encodConf,
	}
}

func GetConfRx() *Conf {
	return &Conf{
		EnableEncoder: false,
		EnableDecoder: true,
	}
}
