package challenge17

import (
	"testing"
	"encoding/base64"
	"bytes"
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

var decodedPlaintexts = make([][]byte, len(plaintexts))

func init() {
	for i, pt := range plaintexts {
		// decrypt the array
		decoded, err := base64.StdEncoding.DecodeString(pt)
		if err != nil {
			panic(err)
		}
		decodedPlaintexts[i] = decoded
	}
}

func TestGetRandomPlaintext(t *testing.T) {
	plaintext := GetRandomPlaintext()
	success := false

	// loop over the decodeds to see if our selected one is there
	for _, pt := range decodedPlaintexts {
		if bytes.Equal(pt, plaintext) {
			success = true
			break
		}
	}

	if !success {
		t.Fail()
	}
}

func TestBlindEncrypt(t *testing.T) {
	enc := BlindEncrypt()
	plaintext := challenge9.Unpad(challenge10.CBCDecrypter(iv, enc, key), 16)
	success := false

	// loop over the decodeds to see if we're in there
	for _, pt := range decodedPlaintexts {
		if bytes.Equal(pt, plaintext) {
			success = true
			break
		}
	}

	if !success {
		t.Fail()
	}
}

func TestDecryptAndCheck(t *testing.T) {
	encrypted := BlindEncrypt()
	if !DecryptAndCheck(encrypted) {
		t.Fail()
	}
}

func TestPaddingOracleAttack(t *testing.T) {
	// test a bunch of times
	for tests := 0; tests < 10; tests++ {
		plaintext := PaddingOracleAttack()
		success := false

		// loop over the decodeds to see if we're in there
		for _, pt := range decodedPlaintexts {
			if bytes.Equal(pt, plaintext) {
				success = true
				break
			}
		}

		if !success {
			t.Fail()
		}
	}
}