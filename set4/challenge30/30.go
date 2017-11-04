package challenge30

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io/ioutil"
	"math/big"
	"net/url"
)

var secret []byte

func init() {
	// read /usr/share/dict/words and grab a random word
	dictBytes, err := ioutil.ReadFile("/usr/share/dict/words")
	if err != nil {
		panic(err)
	}

	// we have bytes from the file, we'll split them up by line
	byteLines := bytes.Split(dictBytes, []byte("\n"))

	// generate a random number for an index
	bigDictIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(byteLines))))
	if err != nil {
		panic(err)
	}
	dictIdx := bigDictIdx.Int64() % int64(len(byteLines))

	secret = byteLines[dictIdx]
}

func MD4MAC(key, message []byte) []byte {
	input := append(key, message...)
	// default registers for MD4
	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xEFCDAB89
	var h2 uint32 = 0x98BADCFE
	var h3 uint32 = 0x10325476
	return Sum(input, h0, h1, h2, h3, len(input))
}

func GenerateQueryString() (msg []byte, hash []byte) {
	msg = []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	return msg, MD4MAC(secret, msg)
}

func CheckValidity(msg, hash []byte) bool {
	// checks to makes sure hash = md4(secret || msg)
	validHash := MD4MAC(secret, msg)
	return bytes.Equal(validHash, hash)
}

func CheckIsValidAdmin(msg []byte, hash []byte) bool {
	// if the hash is valid for the input
	if CheckValidity(msg, hash) {
		// then parse and check for admin=true
		profile, err := url.ParseQuery(string(msg))
		if err != nil {
			panic(err)
		}
		if profile.Get("admin") == "true" {
			return true
		}
		return false
	}
	return false
}

func MDPadLE(input []byte, guessedLength int) []byte {
	// this appears to be the padding scheme
	// it is very opaque though
	var output []byte
	inputLen := guessedLength

	// Padding:  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80

	if inputLen%64 < 56 {
		output = append(input, tmp[0:56-inputLen%64]...)
	} else {
		output = append(input, tmp[0:64+56-inputLen%64]...)
	}

	// Length in bits (length multipled by 8)
	inputLen <<= 3

	// add the length (in bits) of input to the end of the pad for a total of 64 bits
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(inputLen >> (8 * i))
	}
	return append(output, tmp[0:8]...)
}

func GenerateValidAdminMAC(originalInput []byte, originalMD4 []byte) ([]byte, []byte) {
	// first break up the provided hash into 4x4-byte slices
	h0 := binary.LittleEndian.Uint32(originalMD4[0:4])
	h1 := binary.LittleEndian.Uint32(originalMD4[4:8])
	h2 := binary.LittleEndian.Uint32(originalMD4[8:12])
	h3 := binary.LittleEndian.Uint32(originalMD4[12:16])
	// now we can seed the md4 algorithm with the state of an existing hash

	// first we need to decide what our desired payload is
	// in this case it will be ;admin=true
	payload := []byte(";admin=true")
	var generatedMD4 []byte
	var extendedMsg []byte
	originalLen := len(originalInput)

	// we will now guess at the secret length from 1 to 40
	for i := 1; i <= 40; i++ {
		// first pad is len of original plus guessed secret length
		guessedLenOfPrependedMsg := originalLen + i
		gluePad := 64 - (guessedLenOfPrependedMsg % 64)

		// this is len of original + guessed secret length + glue pad + length of extension
		guessedLenOfEverything := guessedLenOfPrependedMsg + gluePad + len(payload)

		// generate a payload with a fixed length and fixed registers
		generatedMD4 = Sum(payload, h0, h1, h2, h3, guessedLenOfEverything)

		// build out what the generatedMD4 would actually be an MD4 of
		extendedMsg = append(MDPadLE(originalInput, guessedLenOfPrependedMsg), payload...)

		if CheckIsValidAdmin(extendedMsg, generatedMD4) {
			break
		}
	}

	return extendedMsg, generatedMD4
}
