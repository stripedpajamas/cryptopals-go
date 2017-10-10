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

func MakeAdmin() {
	// hell yes.
}
