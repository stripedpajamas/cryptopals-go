package challenge14

import (
	"fmt"
	"github.com/stripedpajamas/cryptopals/set1/challenge7"
	"testing"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"bytes"
)

func TestGenerateGarbage(t *testing.T) {
	garbage1 := GenerateGarbage()
	garbage2 := GenerateGarbage()

	if len(garbage1) > 32 {
		t.Fail()
	}

	if bytes.Equal(garbage1, garbage2) {
		t.Fail()
	}
}

func TestEncryptWithJunkySecret(t *testing.T) {
	encrypt1 := EncryptWithJunkySecret([]byte("hello"))
	encrypt2 := EncryptWithJunkySecret([]byte("later"))

	if bytes.Equal(encrypt1, encrypt2) {
		t.Fail()
	}

	decrypted := challenge7.ECBDecrypter(encrypt1, key)

	if !bytes.Contains(decrypted, secret) {
		t.Fail()
	}
}

func TestDupeIndex(t *testing.T) {
	ct := challenge7.ECBEncrypter([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), []byte("YELLOW SUBMARINE"))
	dupeIndex := DupeIndex(ct)

	if dupeIndex != 16 {
		fmt.Println(dupeIndex)
		t.Fail()
	}
}

func TestCrack(t *testing.T) {
	unpaddedOutput := challenge9.Unpad(Crack(), 16)

	// the bytes of the secret are actually available to the module
	// so this check will be easy
	if !bytes.Equal(unpaddedOutput, secret) {
		t.Fail()
	}
}
