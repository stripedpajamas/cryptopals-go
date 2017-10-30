package challenge27

import (
	"github.com/stripedpajamas/cryptopals/set1/challenge3"
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set2/challenge15"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

var key = challenge11.GenerateRandomKey()
var iv = key // <- the important part of the challenge

func GenerateEncURL() []byte {
	url := []byte("comment1=cooking%20MCs;userdata=helloworld;comment2=%20like%20a%20pound%20of%20bacon")
	padded := challenge9.Pad(url, 16)

	return challenge10.CBCEncrypter(iv, padded, key)
}

func CheckPT(input []byte) (bool, []byte) {
	// first decrypt
	decrypted, err := challenge15.RemoveValidPad(challenge10.CBCDecrypter(iv, input, key), 16)
	if err != nil {
		panic(err)
	}

	// checks for high ascii values that wouldn't be normal chars
	// if it finds them it throws back the PT with an error
	for _, char := range decrypted {
		if char > 126 {
			return false, decrypted
		}
	}

	return true, nil
}

func GetKey() []byte {
	// use the fact that the PT is outputted on errors to extract the key
	ct := GenerateEncURL()

	// edit the CT so that block 2 is blank and block 3 is the same as block 1
	empty := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	block1 := ct[:16]

	// clear block 2
	for i := 16; i < 32; i++ {
		ct[i] = empty[i-16]
	}

	// replace block 3 with block 1
	for i := 32; i < 48; i++ {
		ct[i] = block1[i-32]
	}

	// get the error message
	_, msg := CheckPT(ct)

	msgBlock1 := msg[:16]
	msgBlock3 := msg[32:48]

	return challenge3.XorBytes(msgBlock1, msgBlock3)
}
