package challenge24

import (
	"github.com/stripedpajamas/cryptopals/set3/challenge21"
	"testing"
)

func TestExtractBit(t *testing.T) {
	// 12345 = 0011 0000 0011 1001
	// 57    = 0000 0000 0011 1001
	if ExtractBit(12345) != 57 {
		t.Fail()
	}
}

func TestGenerate16BytesFromPRNG(t *testing.T) {
	MT := challenge21.NewMT19937()
	MT.Seed(273)
	if len(Generate16BytesFromPRNG(MT)) != 16 {
		t.Fail()
	}
}

func TestPRNGCipher(t *testing.T) {
	input := "Hello world, I am potato."
	key := 12345

	enc := PRNGCipher([]byte(input), key)

	dec := PRNGCipher(enc, key)

	if string(dec) != input {
		t.Fail()
	}
}
