package challenge24

import (
	"bytes"
	"testing"
)

func TestExtractBit(t *testing.T) {
	// 12345 = 0011 0000 0011 1001
	// 57    = 0000 0000 0011 1001
	if ExtractBit(12345) != 57 {
		t.Fail()
	}
}

func TestPRNGCipher(t *testing.T) {
	input := "Hello world, I am potato."
	key := 12345

	enc := PRNGCipher([]byte(input), key)

	dec := PRNGCipher(enc, key)

	if string(dec) != input {
		t.Fail()
	}
}

func TestGenerateRandomSeed(t *testing.T) {
	if GenerateRandomSeed() > 0xFFFF {
		t.Fail()
	}
}

func TestPRNGEncryptWithGarbage(t *testing.T) {
	pt1 := PRNGEncryptWithGarbage([]byte("hello"))
	pt2 := PRNGEncryptWithGarbage([]byte("later"))

	if bytes.Equal(pt1, pt2) {
		t.Fail()
	}

	dec := PRNGCipher(pt2, keyseed)

	if !bytes.Contains(dec, []byte("later")) {
		t.Fail()
	}
}

func TestRecoverKeySeed(t *testing.T) {
	// https://cryptopals.com/sets/3/challenges/24
	recovered := RecoverKeySeed()
	if recovered != keyseed {
		t.Fail()
	}
}
