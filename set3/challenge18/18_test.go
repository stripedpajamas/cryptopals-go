package challenge18

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestIncrementCounter(t *testing.T) {
	littleEndian := []byte{0, 0, 0, 0}
	bigEndian := []byte{0, 0, 0, 0}

	IncrementCounter(littleEndian, "little")
	IncrementCounter(bigEndian, "big")

	if !bytes.Equal(littleEndian, []byte{1, 0, 0, 0}) {
		t.Fail()
	}
	if !bytes.Equal(bigEndian, []byte{0, 0, 0, 1}) {
		t.Fail()
	}
}

func TestCTR(t *testing.T) {
	// https://cryptopals.com/sets/3/challenges/18
	b64Input := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	input, err := base64.StdEncoding.DecodeString(b64Input)
	if err != nil {
		t.Fail()
	}

	output := CTR(input, []byte("YELLOW SUBMARINE"), []byte{0, 0, 0, 0, 0, 0, 0, 0})

	if string(output) != "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby " {
		t.Fail()
	}
}
