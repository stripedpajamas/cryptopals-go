package challenge26

import (
	"testing"

	"github.com/stripedpajamas/cryptopals/set3/challenge18"
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

	decrypted := challenge18.CTR(generatedString, key, nonce)
	if string(decrypted) != expected {
		t.Fail()
	}
}

func TestIsAdmin(t *testing.T) {
	normalInput := GenerateString("hello")
	if IsAdmin(normalInput) {
		t.Fail()
	}

	adminInput := challenge18.CTR([]byte("admin=true"), key, nonce)
	if !IsAdmin(adminInput) {
		t.Fail()
	}

	badUserInput := GenerateString("admin=true")
	if IsAdmin(badUserInput) {
		t.Fail()
	}
}

func TestMakeAdmin(t *testing.T) {
	// https://cryptopals.com/sets/4/challenges/26
	adminProfile := MakeAdmin()

	if !IsAdmin(adminProfile) {
		t.Fail()
	}
}
