package challenge2

import (
	"testing"
)

func TestXor(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/2
	c2inputA := "1c0111001f010100061a024b53535009181c"
	c2inputB := "686974207468652062756c6c277320657965"
	c2ExpectedOutput := "746865206b696420646f6e277420706c6179"

	c2output, err := Xor(c2inputA, c2inputB)
	if err != nil || c2output != c2ExpectedOutput {
		t.Fail()
	}
}
