package challenge26

import (
	"net/url"
	"regexp"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set3/challenge18"
)

var key = challenge11.GenerateRandomKey()
var nonce = []byte{0, 0, 0, 0, 0, 0, 0, 0}
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

	return challenge18.CTR(appended, key, nonce)
}

func IsAdmin(input []byte) bool {
	// first decrypt
	decrypted := challenge18.CTR(input, key, nonce)

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
	// comment1=cooking%20MCs;userdata= is 32 bytes long, my input will be pos 32
	// i need to get ;admin=true in
	// i can make a fake block and know the keystream for those bytes (my input ^ resulting ct)
	// and then change the letters i want into keystream ^ desired input

	// 12 A's, we'll replace the last 11 of them
	enc := GenerateString("AAAAAAAAAAAA")
	adminPayload := []byte(";admin=true")

	// i want the last 11 chars of my block to be my admin payload
	// so starting at 48 - 11 = 37
	// and I need to edit the 2nd block to make changes to the 3rd so -16 = 21
	// char code 65 is my plaintext (always an A)

	for i, x := range adminPayload {
		// enc[i+33] ^ 65 (which is an A) is the keystream byte
		// x is what i want it to be
		enc[i+33] = enc[i+33] ^ 65 ^ x
	}

	return enc
}
