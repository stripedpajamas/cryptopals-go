package challenge3

import (
	"testing"
	"bytes"
	"encoding/hex"
)

func TestScoreString(t *testing.T) {
	// it should give a score which represents the average deviance from normal english
	c3input1 := "e"
	// an input of "e" means 100% letter e. normal is 12.702%, so deviance should be 87.298%
	c3ExpectedOutput := 0.87298

	c3output := ScoreString(c3input1)
	if c3output != c3ExpectedOutput {
		t.Fail()
	}
}

func TestXorBytes(t *testing.T) {
	// same as challenge 2 but inputs and outputs byte arrays
	// instead of hex strings (saves some time for the crack)
	c3inputA := []byte{28, 1, 17, 0, 31, 1, 1, 0, 6, 26, 2, 75, 83, 83, 80, 9, 24, 28}
	c3inputB := []byte{104, 105, 116, 32, 116, 104, 101, 32, 98, 117, 108, 108, 39, 115, 32, 101, 121, 101}
	c3ExpectedOutput := []byte{116, 104, 101, 32, 107, 105, 100, 32, 100, 111, 110, 39, 116, 32, 112, 108, 97, 121}

	c3output := XorBytes(c3inputA, c3inputB)
	if bytes.Compare(c3output, c3ExpectedOutput) != 0 {
		t.Fail()
	}
}

func TestCrackSingleKeyXOR(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/2
	c3input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	c3inputBytes, _ := hex.DecodeString(c3input)
	c3ExpectedOutput := "Cooking MC's like a pound of bacon"

	c3output := CrackSingleKeyXOR(c3inputBytes)
	if c3output.Text != c3ExpectedOutput {
		t.Fail()
	}
}

var benchmarkResult *Processed

func BenchmarkCrackSingleKeyXOR(b *testing.B) {
	// set up
	c3input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	c3inputBytes, _ := hex.DecodeString(c3input)
	var c3output *Processed

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c3output = CrackSingleKeyXOR(c3inputBytes)
	}

	benchmarkResult = c3output
}
