package challenge18

import (
	"bytes"

	"github.com/stripedpajamas/cryptopals/set1/challenge7"
)

func IncrementCounter(target []byte, endian string) []byte {
	var i int
	if endian == "little" {
		// little endian
		for i = 0; i < len(target) && target[i] == 255; i++ {
			target[i] = 0
		}
	} else if endian == "big" {
		// big endian
		for i = len(target) - 1; i >= 0 && target[i] == 255; i-- {
			target[i] = 0
		}
	}
	if ^i != 0 {
		target[i]++
	}

	return target
}

func CTR(input, key, nonce []byte) []byte {
	// this CTR implementation is for 16 byte blocks
	// ala cryptopals challenges

	inputLen := len(input)
	output := make([]byte, inputLen)

	counter := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	var keystream, inputBuff bytes.Buffer

	// initialize buffers
	inputBuff.Write(input)
	keystream.Write(challenge7.ECBEncrypter(append(nonce, counter...), key))

	for i := 0; i < inputLen; i++ {
		in, err := inputBuff.ReadByte()
		if err != nil {
			panic(err)
		}
		// if we run out of keystream, refill
		if keystream.Len() == 0 {
			// we increment counter during refill because the keystream is always 16 bytes
			// which means when we run out it's because we're at the next "block"
			counter = IncrementCounter(counter, "little")
			keystream.Write(challenge7.ECBEncrypter(append(nonce, counter...), key))
		}
		ks, err := keystream.ReadByte()
		if err != nil {
			panic(err)
		}

		// output is input byte xored with keystream byte
		output[i] = in ^ ks
	}

	return output
}
