package challenge9

import (
	"testing"
	"bytes"
)

func TestPad(t *testing.T) {
	// http://cryptopals.com/sets/2/challenges/9
	c9input := []byte("YELLOW SUBMARINE")
	c9ExpectedOutput := append(c9input, []byte{4, 4, 4, 4}...)

	c9output := Pad(c9input, 20)

	if bytes.Compare(c9output, c9ExpectedOutput) != 0 {
		t.Fail()
	}
}