package challenge21

import (
	"testing"
)

func TestMt19937_Extract(t *testing.T) {
	MT0 := NewMT19937()
	MT0.Seed(123)
	MT0.Extract() // get rid of the first result for the loop later

	MT1 := NewMT19937()
	MT1.Seed(123)
	output1 := MT1.Extract()

	MT2 := NewMT19937()
	MT2.Seed(321)
	output2 := MT2.Extract()

	// same seeds should result in same results
	for i := 0; i < 32; i++ {
		if MT0.Extract() != MT1.Extract() {
			t.Fail()
		}
	}

	// different seeds should result in different first result
	if output2 == output1 {
		t.Fail()
	}
}
