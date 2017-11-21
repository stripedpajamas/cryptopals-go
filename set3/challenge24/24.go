package challenge24

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set2/challenge14"
	"github.com/stripedpajamas/cryptopals/set3/challenge21"
)

var keyseed int = GenerateRandomSeed()

func ExtractBit(x int) byte {
	// takes an int from the PRNG and returns the 8 least significant bytes
	return byte(0xFF & x)
}

func PRNGCipher(input []byte, key int) []byte {
	// key is supposed to be 16-bit
	if key > 0xFFFF {
		panic("Key must be 16-bit")
	}
	MT := challenge21.NewMT19937()
	MT.Seed(key)

	inputLen := len(input)
	output := make([]byte, inputLen)

	var inputBuff bytes.Buffer

	// initialize buffers
	inputBuff.Write(input)

	for i := 0; i < inputLen; i++ {
		in, err := inputBuff.ReadByte()
		if err != nil {
			panic(err)
		}
		ks := ExtractBit(MT.Extract())
		// output is input byte xored with keystream byte
		output[i] = in ^ ks
	}

	return output
}

func GenerateRandomSeed() int {
	key, err := rand.Int(rand.Reader, big.NewInt(0xFFFF))
	if err != nil {
		panic(err)
	}
	return int(key.Int64())
}

func PRNGEncryptWithGarbage(plaintext []byte) []byte {
	prefixGarbage := challenge14.GenerateGarbage()
	input := append(prefixGarbage, plaintext...)

	return PRNGCipher(input, keyseed)
}

func RecoverKeySeed() int {
	// to recover key we'll pass in a known ct of a bunch of repeated chars
	// since it's XOR'd, we'll know the backend of the keystream trivially
	// then we can loop through every 16-bit value and seed an MT until it
	// produces those same values at the index we grabbed

	// 14 A's
	payload := []byte("AAAAAAAAAAAAAA")
	ciphertext := PRNGEncryptWithGarbage(payload)
	ctLen := len(ciphertext)

	// our payload begins at idx len - 14
	// we'll xor the last 14 bytes with 65 (A) to get the last 14 bytes of the keystream
	ksPart := make([]byte, 14)
	for i, j := ctLen-14, 0; i < ctLen; i, j = i+1, j+1 {
		ksPart[j] = ciphertext[i] ^ 65
	}

	// make a new PRNG
	MT := challenge21.NewMT19937()
	var recoveredSeed int
	// now loop through possible seeds
	for i := 0; i <= 0xFFFF; i++ {
		MT.Seed(i)
		generatedKeystream := make([]byte, ctLen)
		for j := 0; j < ctLen; j++ {
			generatedKeystream[j] = ExtractBit(MT.Extract())
		}
		if bytes.Equal(generatedKeystream[ctLen-14:], ksPart) {
			recoveredSeed = i
			break
		}
	}

	return recoveredSeed
}

// TODO random "password reset token" part of this challenge
