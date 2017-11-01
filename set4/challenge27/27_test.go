package challenge27

import (
	"bytes"
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge15"
	"testing"
)

func TestGenerateEncURL(t *testing.T) {
	generatedString := GenerateEncURL()
	expected := "comment1=cooking%20MCs;userdata=helloworld;comment2=%20like%20a%20pound%20of%20bacon"

	decrypted, err := challenge15.RemoveValidPad(challenge10.CBCDecrypter(iv, generatedString, key), 16)
	if err != nil {
		t.Fail()
	}
	if string(decrypted) != expected {
		t.Fail()
	}
}

func TestCheckPT(t *testing.T) {
	// should return true if everything is normal
	generatedString := GenerateEncURL()
	checked, rejectedInput := CheckPT(generatedString)

	if !checked || rejectedInput != nil {
		t.Fail()
	}

	// send some crap
	for i := 0; i < len(generatedString)/2; i++ {
		generatedString[i] = 123
	}

	checked, rejectedInput = CheckPT(generatedString)
	if checked {
		t.Fail()
	}

	decrypted, err := challenge15.RemoveValidPad(challenge10.CBCDecrypter(iv, generatedString, key), 16)
	if err != nil {
		t.Fail()
	}

	if !bytes.Equal(rejectedInput, decrypted) {
		t.Fail()
	}
}

func TestGetKey(t *testing.T) {
	// https://cryptopals.com/sets/4/challenges/27
	if !bytes.Equal(GetKey(), key) {
		t.Fail()
	}
}
