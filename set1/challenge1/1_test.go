package challenge1

import (
	"testing"
)

func TestHex2b64(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/1
	c1input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	c1ExpectedOutput := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	c1output, err := Hex2b64(c1input)

	if err != nil || c1output != c1ExpectedOutput {
		t.Fail()
	}
}
