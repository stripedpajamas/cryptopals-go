package challenge21

import (
	"testing"
)

func TestExtract(t *testing.T) {
	Seed(123)
	output0 := Extract()

	Seed(123)
	output1 := Extract()

	Seed(321)
	output2 := Extract()

	// same seeds should result in same first result
	if output0 != output1 {
		t.Fail()
	}

	// different seeds should result in different first result
	if output2 == output1 {
		t.Fail()
	}
}
