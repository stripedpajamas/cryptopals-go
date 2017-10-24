package challenge24

import (
	"bytes"
	"github.com/stripedpajamas/cryptopals/set3/challenge21"
)

func ExtractBit(x int) byte {
	// takes an int from the PRNG and returns the 8 least significant bytes
	return byte(0xFF & x)
}

func Generate16BytesFromPRNG(prng challenge21.MT19937) []byte {
	outputBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		outputBytes[i] = ExtractBit(prng.Extract())
	}
	return outputBytes
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

	var keystream, inputBuff bytes.Buffer

	// initialize buffers
	inputBuff.Write(input)
	keystream.Write(Generate16BytesFromPRNG(MT))

	for i := 0; i < inputLen; i++ {
		in, err := inputBuff.ReadByte()
		if err != nil {
			panic(err)
		}
		// if we run out of keystream, refill
		if keystream.Len() == 0 {
			keystream.Write(Generate16BytesFromPRNG(MT))
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
