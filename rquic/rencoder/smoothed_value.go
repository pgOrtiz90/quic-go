package rencoder

//package main

import (
	//"fmt"
	"sync"
)

type smoothedValue struct {
	mu          sync.Mutex
	values      []float64
	ind         int
	cumValue    float64
	numPeriods  int
	numPeriodsF float64
}

func (s *smoothedValue) Update(newValue float64) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ind = (s.ind + 1) % s.numPeriods
	s.cumValue += newValue - s.values[s.ind]
	s.values[s.ind] = newValue
	return s.cumValue / s.numPeriodsF
}

func (s *smoothedValue) Value() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cumValue / s.numPeriodsF
}

func (s *smoothedValue) Reset() {
	s.mu.Lock()
	s.cumValue = 0
	for i := range s.values {
		s.values[i] = 0
	}
	s.mu.Unlock()
}

func (s *smoothedValue) ChangeNumPeriods(newNum int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if newNum == s.numPeriods {
		return
	}

	next := s.ind + 1

	if numDif := newNum - s.numPeriods; numDif > 0 {
		s.values = append(s.values[:next], append(make([]float64, numDif), s.values[next:]...)...)
		s.numPeriods = newNum
		s.numPeriodsF = float64(newNum)
		return
	}

	//if newNum < s.numPeriods {
	nextValid := (s.ind + s.numPeriods - newNum + 1) % s.numPeriods

	// update s.cumValue
	if newNum > s.numPeriods/2 {
		for i := next; i != nextValid; i = (i + 1) % s.numPeriods {
			s.cumValue -= s.values[i]
		}
	} else { // if there is too much to subtract, sum what remains
		s.cumValue = 0
		for i := nextValid; i != next; i = (i + 1) % s.numPeriods {
			s.cumValue += s.values[i]
		}
	}

	// remove oldest elements from s.values
	if nextValid > s.ind {
		s.values = append(s.values[:next], s.values[nextValid:]...)
	} else {
		s.values = s.values[nextValid:next]
	}

	// update s.ind if necessary
	if nextValid < next {
		if 0 < nextValid {
			s.ind -= nextValid
		}
	}

	s.numPeriods = newNum
	s.numPeriodsF = float64(newNum)
	//}
}

func NewSmoothedValue(numPeriods int) *smoothedValue {
	return &smoothedValue{
		numPeriods:  numPeriods,
		numPeriodsF: float64(numPeriods),
		values:      make([]float64, numPeriods),
		ind:         0,
		cumValue:    0,
	}
}
