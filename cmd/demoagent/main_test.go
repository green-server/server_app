package main

import (
	"testing"
	"time"
)

func TestReadingsStayInRangeAndRepeat(t *testing.T) {
	start := time.Date(2026, 11, 7, 0, 0, 0, 0, kst)
	for name, s := range scenarios {
		for at := start; at.Before(start.Add(24 * time.Hour)); at = at.Add(time.Minute) {
			cpu, mem, watts := s.reading(at)
			if cpu < 0 || cpu > 100 || mem <= 0 || mem > 100 || watts < s.Idle || watts > s.Max {
				t.Fatalf("%s at %s: cpu %v mem %v watts %v", name, at, cpu, mem, watts)
			}
			if _, _, again := s.reading(at); again != watts {
				t.Fatalf("%s at %s is not repeatable", name, at)
			}
		}
	}
}

func TestEveryReadingIsMarkedEstimated(t *testing.T) {
	for _, s := range scenarios {
		if m := metrics(s, time.Now(), true); m["isEstimated"] != true {
			t.Fatal(s.Name)
		}
	}
}

func TestScenariosPeakAtDifferentTimes(t *testing.T) {
	web := scenarios["web"]
	game := scenarios["game"]
	noon := time.Date(2026, 11, 7, 14, 0, 0, 0, kst)
	night := time.Date(2026, 11, 7, 21, 30, 0, 0, kst)
	if _, _, a := web.reading(noon); a < web.Max*0.8 {
		t.Errorf("web at noon %v", a)
	}
	if _, _, a := game.reading(night); a < game.Max*0.9 {
		t.Errorf("game at night %v", a)
	}
	if a, b := scenarios["batch"].Load(time.Date(2026, 11, 7, 3, 5, 0, 0, kst)), scenarios["batch"].Load(time.Date(2026, 11, 7, 4, 0, 0, 0, kst)); a < 0.5 || b > 0.1 {
		t.Errorf("batch %v %v", a, b)
	}
}
