package main

import (
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	s := make([]time.Duration, 30)
	for i := range s {
		s[i] = time.Duration(i + 1) // 1..30
	}
	for _, tc := range []struct {
		p    float64
		want time.Duration
	}{{0.5, 15}, {0.95, 29}, {1, 30}, {0.01, 1}} {
		if got := percentile(s, tc.p); got != tc.want {
			t.Errorf("p%.2f = %d, want %d", tc.p, got, tc.want)
		}
	}
}
