package challenge15

import (
	"bytes"
	"testing"
)

func TestValidatePad(t *testing.T) {
	// https://cryptopals.com/sets/2/challenges/15
	validInput := append([]byte("ICE ICE BABY"), []byte{4, 4, 4, 4}...)

	output1, err := RemoveValidPad(validInput, 16)

	if err != nil {
		t.Fail()
	}

	if !bytes.Equal([]byte("ICE ICE BABY"), output1) {
		t.Fail()
	}

	invalidInput1 := append([]byte("ICE ICE BABY"), []byte{5, 5, 5, 5}...)
	_, err = RemoveValidPad(invalidInput1, 16)
	if err == nil {
		t.Fail()
	}

	invalidInput2 := append([]byte("ICE ICE BABY"), []byte{1, 2, 3, 4}...)
	_, err = RemoveValidPad(invalidInput2, 16)
	if err == nil {
		t.Fail()
	}
}
