package challenge9

import (
	"bytes"
	"testing"
)

func TestPad(t *testing.T) {
	// http://cryptopals.com/sets/2/challenges/9
	c9input := []byte("YELLOW SUBMARINE")
	c9ExpectedOutput := append(c9input, []byte{4, 4, 4, 4}...)

	c9output := Pad(c9input, 20)

	if !bytes.Equal(c9output, c9ExpectedOutput) {
		t.Fail()
	}
}

func TestUnpad(t *testing.T) {
	input := append([]byte("YELLOW SUBMARINE"), []byte{4, 4, 4, 4}...)
	expectedOutput := []byte("YELLOW SUBMARINE")

	output := Unpad(input, 20)

	if !bytes.Equal(output, expectedOutput) {
		t.Fail()
	}
}
