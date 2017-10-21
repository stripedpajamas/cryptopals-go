package challenge21

import (
	"testing"
)

func TestExtract(t *testing.T) {
	Seed(123)
	outputs := make([]int, 10)
	for i := 0; i < 10; i++ {
		outputs[i] = Extract()
	}

	for i, num := range outputs {
		for j, otherNum := range outputs {
			if j == i {
				continue
			}
			if num == otherNum {
				// assuming that there shouldn't be a repeated number
				// in 10 samples
				t.Fail()
			}
		}
	}
}
