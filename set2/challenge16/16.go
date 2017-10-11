package challenge16

import (
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set2/challenge15"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"net/url"
	"regexp"
)

var key = challenge11.GenerateRandomKey()
var iv = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var prepender = []byte("comment1=cooking%20MCs;userdata=")
var appender = []byte(";comment2=%20like%20a%20pound%20of%20bacon")

func SanitizeInput(input string) string {
	re := regexp.MustCompile("[;=]")
	return re.ReplaceAllLiteralString(input, "")
}

func GenerateString(input string) []byte {
	safeInput := []byte(SanitizeInput(input))
	prepended := append(prepender, safeInput...)
	appended := append(prepended, appender...)
	padded := challenge9.Pad(appended, 16)

	return challenge10.CBCEncrypter(iv, padded, key)
}

func IsAdmin(input []byte) bool {
	// first decrypt
	decrypted, err := challenge15.RemoveValidPad(challenge10.CBCDecrypter(iv, input, key), 16)
	if err != nil {
		panic(err)
	}

	// then parse and check for admin=true
	profile, err := url.ParseQuery(string(decrypted))
	if err != nil {
		panic(err)
	}
	if profile.Get("admin") == "true" {
		return true
	}
	return false
}

func MakeAdmin() []byte {
	// comment1=cooking%20MCs;userdata= is 32 bytes long, my input begins block 3 always
	// i need to get ;admin=true in my block
	// i know that block 2 will be xor'd with my block
	// block 2 is %20MCs;userdata=
	// A = block 2 char
	// X = plaintext I enter
	// Z = letter I want
	// set A to A^X^Z

	// start with something i can easily manipulate - 16 A's
	enc := GenerateString("AAAAAAAAAAAAAAAA")
	adminPayload := []byte(";admin=true")

	// i want the last 11 chars of my block to be my admin payload
	// so starting at 48 - 11 = 37
	// and I need to edit the 2nd block to make changes to the 3rd so -16 = 21
	// char code 65 is my plaintext (always an A)

	for i, x := range adminPayload {
		enc[i+21] = enc[i+21] ^ 65 ^ x
	}

	return enc
}
