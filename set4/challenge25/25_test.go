package challenge25

import (
	"bytes"
	"github.com/stripedpajamas/cryptopals/set3/challenge18"
	"io/ioutil"
	"testing"
)

var globalPlaintext []byte

func init() {
	var err error
	globalPlaintext, err = ioutil.ReadFile("25_decoded.txt")
	if err != nil {
		panic(err)
	}
}

func TestEncryptSecretWithCTR(t *testing.T) {
	enc := EncryptSecretWithCTR(globalPlaintext)
	dec := challenge18.CTR(enc, globalKey, globalNonce)

	if !bytes.Equal(dec, globalPlaintext) {
		t.Fail()
	}
}

func TestEdit(t *testing.T) {
	input := []byte("HELLO POTATO FACE")
	key := []byte("YELLOW SUBMARINE")
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	enc := challenge18.CTR(input, key, nonce)
	edited := Edit(enc, key, nonce, []byte("TOMATO"), 6)
	dec := challenge18.CTR(edited, key, nonce)

	if string(dec) != "HELLO TOMATO FACE" {
		t.Fail()
	}
}

func TestEditAPI(t *testing.T) {
	input := []byte("HELLO POTATO FACE")
	enc := challenge18.CTR(input, globalKey, globalNonce)
	edited := EditAPI(enc, []byte("TOMATO"), 6)
	dec := challenge18.CTR(edited, globalKey, globalNonce)

	if string(dec) != "HELLO TOMATO FACE" {
		t.Fail()
	}
}

func TestRecoverPTFromAPI(t *testing.T) {
	// https://cryptopals.com/sets/4/challenges/25
	enc := EncryptSecretWithCTR(globalPlaintext)
	recovered := RecoverPTFromAPI(enc)
	if !bytes.Equal(recovered, globalPlaintext) {
		t.Fail()
	}
}
