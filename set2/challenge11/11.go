package challenge11

import (
	"bytes"
	"crypto/rand"
	"github.com/stripedpajamas/cryptopals/set1/challenge7"
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"math/big"
)

type RandomlyEncrypted struct {
	ciphertext []byte
	mode       string
}

func GenerateRandomKey() []byte {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

func RandomlyPad(plaintext []byte) []byte {
	// generate random length for front and back
	appendLen, err := rand.Int(rand.Reader, big.NewInt(5))
	if err != nil {
		panic(err)
	}
	prependLen, err := rand.Int(rand.Reader, big.NewInt(5))
	if err != nil {
		panic(err)
	}

	// make the byte arrays
	appendPT := make([]byte, appendLen.Int64()+5)
	prependPT := make([]byte, prependLen.Int64()+5)

	// read random bytes into them
	_, aRandErr := rand.Read(appendPT)
	if aRandErr != nil {
		panic(err)
	}

	_, pRandErr := rand.Read(prependPT)
	if pRandErr != nil {
		panic(err)
	}

	// attach them to plaintext
	plaintext = append(appendPT, plaintext...)
	plaintext = append(plaintext, prependPT...)

	return plaintext
}

func RandomlyEncrypt(plaintext []byte) RandomlyEncrypted {
	key := GenerateRandomKey()
	plaintext = RandomlyPad(plaintext)

	r := []byte{0}
	_, err := rand.Read(r)
	if err != nil {
		panic(err)
	}

	// pad the plaintext because we've just screwed it up a bit
	plaintext = challenge9.Pad(plaintext, 16)

	// randomly use either CBC or ECB
	if r[0]%2 == 0 {
		return RandomlyEncrypted{
			ciphertext: challenge7.ECBEncrypter(plaintext, key),
			mode:       "ECB",
		}
	} else {
		return RandomlyEncrypted{
			ciphertext: challenge10.CBCEncrypter(GenerateRandomKey(), plaintext, key),
			mode:       "CBC",
		}
	}
}

func DetectMode(ciphertext []byte) string {
	// find repeated blocks
	for j := 0; j < len(ciphertext); j += 16 {
		block := ciphertext[j : j+16]
		if bytes.Count(ciphertext, block) > 1 {
			return "ECB"
		}
	}
	return "CBC"
}
