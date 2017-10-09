package challenge12

import (
	"testing"
)

func TestDetectBlockSize(t *testing.T) {
	if DetectBlockSize() != 16 {
		t.Fail()
	}
}

func TestDetectECB(t *testing.T) {
	if DetectECB(16) != true {
		t.Fail()
	}
}

func TestCrack(t *testing.T) {
	// https://cryptopals.com/sets/2/challenges/12

	c12ExpectedOutput := `Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
`
	c12output := Crack()
	// the padding will be messed up so we'll just trim it off
	// that's not the point of this exercise
	c12output = c12output[:138]

	if string(c12output) != c12ExpectedOutput {
		t.Fail()
	}
}

var benchmarkResult []byte

func BenchmarkCrack(b *testing.B) {
	var c12output []byte

	for i := 0; i < b.N; i++ {
		c12output = Crack()
	}

	benchmarkResult = c12output
}
