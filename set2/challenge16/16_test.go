package challenge16

import (
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge15"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"testing"
)

func TestSanitizeInput(t *testing.T) {
	goodInput := "hello world"
	if SanitizeInput(goodInput) != goodInput {
		t.Fail()
	}

	scaryInput := "hello; world"
	if SanitizeInput(scaryInput) != goodInput {
		t.Fail()
	}

	badInput := "admin=true"
	if SanitizeInput(badInput) != "admintrue" {
		t.Fail()
	}
}

func TestGenerateString(t *testing.T) {
	generatedString := GenerateString("hello")
	expected := "comment1=cooking%20MCs;userdata=hello;comment2=%20like%20a%20pound%20of%20bacon"

	decrypted, err := challenge15.RemoveValidPad(challenge10.CBCDecrypter(iv, generatedString, key), 16)
	if err != nil {
		t.Fail()
	}
	if string(decrypted) != expected {
		t.Fail()
	}
}

func TestIsAdmin(t *testing.T) {
	normalInput := GenerateString("hello")
	if IsAdmin(normalInput) {
		t.Fail()
	}

	adminInput := challenge10.CBCEncrypter(iv, challenge9.Pad([]byte("admin=true"), 16), key)
	if !IsAdmin(adminInput) {
		t.Fail()
	}

	badUserInput := GenerateString("admin=true")
	if IsAdmin(badUserInput) {
		t.Fail()
	}
}
