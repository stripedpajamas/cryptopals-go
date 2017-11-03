package challenge29

import (
	"bytes"
	"github.com/stripedpajamas/cryptopals/set4/challenge28"
	"testing"
)

func TestMDPad(t *testing.T) {
	input := []byte("hello world")
	output := []byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88}

	// normal padding
	if !bytes.Equal(MDPad(input, len(input)), output) {
		t.Fail()
	}

	// but can also say i want to pad the input as if it were 13 chars (output has two less 0x00s and ends with 104
	output = []byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104}
	if !bytes.Equal(MDPad(input, 13), output) {
		t.Fail()
	}
}

func TestCheckValidity(t *testing.T) {
	// this just checks whether a hash was created (presumably) with the secret
	input := []byte("lolz")
	validHash := challenge28.SHA1MAC(secret, input)

	if !CheckValidity(input, validHash) {
		t.Fail()
	}

	invalidHash := challenge28.SHA1MAC([]byte("012345_not_the_secret"), input)

	if CheckValidity(input, invalidHash) {
		t.Fail()
	}
}

func TestGenerateQueryString(t *testing.T) {
	qs := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	_, hash := GenerateQueryString()
	validHash := challenge28.SHA1MAC(secret, qs)
	if !bytes.Equal(hash[0:20], validHash[0:20]) {
		t.Fail()
	}
}

func TestGenerateValidAdminMAC(t *testing.T) {
	originalMsg, originalHash := GenerateQueryString()
	extMsg, extHash := GenerateValidAdminMAC(originalMsg, originalHash)

	if !CheckIsValidAdmin(extMsg, extHash) {
		t.Fail()
	}
}
