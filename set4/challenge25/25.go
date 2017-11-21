package challenge25

import (
	"bytes"
	"math"

	"github.com/stripedpajamas/cryptopals/set1/challenge7"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set3/challenge18"
)

var globalKey []byte = challenge11.GenerateRandomKey()
var globalNonce []byte = challenge11.GenerateRandomKey()[:8]

func EncryptSecretWithCTR(plaintext []byte) []byte {
	return challenge18.CTR(plaintext, globalKey, globalNonce)
}

func Edit(ciphertext, key, nonce, new []byte, offset int) []byte {
	// edit computes the keystream at the desired offset
	// and then replaces the ciphertext at the offset with the
	// newly encrypted 'new' pt bytes

	ctLen := len(ciphertext)
	newLen := len(new)

	// don't be stupid
	if offset > ctLen {
		panic("Offset must be less than the length of the ciphertext")
	}

	// figure out how many increments to the counter we need and initialize
	counter := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	inc := int(math.Floor(float64(offset / 16)))
	keystreamOffset := offset % 16

	for i := 0; i < inc; i++ {
		challenge18.IncrementCounter(counter, "little")
	}

	// set up the output
	outputLen := ctLen

	// if the passed in PT would extend beyond the end of the current ct,
	// we want the output to accommodate the stretch
	if newLen >= ctLen-offset {
		outputLen = offset + newLen
	}
	output := make([]byte, outputLen)
	// hydrate
	copy(output, ciphertext)

	var keystream, inputBuff bytes.Buffer

	// initialize buffers
	inputBuff.Write(new)
	keystream.Write(challenge7.ECBEncrypter(append(nonce, counter...), key)[keystreamOffset:])

	for i := 0; i < newLen; i++ {
		in, err := inputBuff.ReadByte()
		if err != nil {
			panic(err)
		}
		// if we run out of keystream, refill
		if keystream.Len() == 0 {
			// we increment counter during refill because the keystream is always 16 bytes
			// which means when we run out it's because we're at the next "block"
			counter = challenge18.IncrementCounter(counter, "little")
			keystream.Write(challenge7.ECBEncrypter(append(nonce, counter...), key))
		}
		ks, err := keystream.ReadByte()
		if err != nil {
			panic(err)
		}

		// output is input byte xored with keystream byte
		output[i+offset] = in ^ ks
	}

	return output
}

func EditAPI(ciphertext, new []byte, offset int) []byte {
	return Edit(ciphertext, globalKey, globalNonce, new, offset)
}

func RecoverPTFromAPI(ciphertext []byte) []byte {
	ctLen := len(ciphertext)
	plaintext := make([]byte, ctLen)
	aPayload := bytes.Repeat([]byte("A"), ctLen)

	edited := EditAPI(ciphertext, aPayload, 0)

	// we can get the full keystream by xoring the new CT with what we know our payload was (65)
	// and we can get the original PT from xoring with that derived KS
	for i, editByte := range edited {
		plaintext[i] = (editByte ^ 65) ^ ciphertext[i]
	}

	return plaintext
}
