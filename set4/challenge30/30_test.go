package challenge30

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/crypto/md4"
)

func TestSum(t *testing.T) {
	input := []byte("hello world")

	// default registers for MD4
	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xEFCDAB89
	var h2 uint32 = 0x98BADCFE
	var h3 uint32 = 0x10325476

	mySum := Sum(input, h0, h1, h2, h3, len(input))

	h := md4.New()
	data := "hello world"
	io.WriteString(h, data)
	realSum := h.Sum(nil)

	if !bytes.Equal(mySum, realSum) {
		t.Fail()
	}
}

func TestMDPadLE(t *testing.T) {
	input := []byte("hello world")
	output := []byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0}

	// normal padding
	if !bytes.Equal(MDPadLE(input, len(input)), output) {
		t.Fail()
	}

	// but can also say i want to pad the input as if it were 13 chars (output has two less 0x00s and ends with 104
	output = []byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(MDPadLE(input, 13), output) {
		t.Fail()
	}
}

func TestCheckValidity(t *testing.T) {
	// this just checks whether a hash was created (presumably) with the secret
	input := []byte("lolz")
	validHash := MD4MAC(secret, input)

	if !CheckValidity(input, validHash) {
		t.Fail()
	}

	invalidHash := MD4MAC([]byte("012345_not_the_secret"), input)

	if CheckValidity(input, invalidHash) {
		t.Fail()
	}
}

func TestGenerateQueryString(t *testing.T) {
	qs := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	_, hash := GenerateQueryString()
	validHash := MD4MAC(secret, qs)
	if !bytes.Equal(hash, validHash) {
		t.Fail()
	}
}

func TestGenerateValidAdminMAC(t *testing.T) {
	// https://cryptopals.com/sets/4/challenges/30
	originalMsg, originalHash := GenerateQueryString()
	extMsg, extHash := GenerateValidAdminMAC(originalMsg, originalHash)

	if !CheckIsValidAdmin(extMsg, extHash) {
		t.Fail()
	}
}
