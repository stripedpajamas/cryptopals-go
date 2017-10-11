package challenge17

import (
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"math/big"
	"crypto/rand"
	"encoding/base64"
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge15"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

var key = challenge11.GenerateRandomKey()
var iv = challenge11.GenerateRandomKey()
var plaintexts = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func GetRandomPlaintext() []byte {
	// generate random idx of plaintext array
	ptIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(plaintexts))))
	if err != nil {
		panic(err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(plaintexts[ptIdx.Int64()])
	if err != nil {
		panic(err)
	}

	return plaintext
}

func BlindEncrypt() []byte {
	plaintext := challenge9.Pad(GetRandomPlaintext(), 16)
	return challenge10.CBCEncrypter(iv, plaintext, key)
}

func DecryptAndCheck(ciphertext []byte) bool {
	// decrypts, checks padding, returns true if it's good
	plaintext := challenge10.CBCDecrypter(iv, ciphertext, key)
	_, err := challenge15.RemoveValidPad(plaintext, 16)
	if err != nil {
		return false
	}
	return true
}

//func PaddingOracleAttack() []byte {
//	ciphertext := BlindEncrypt()
//}