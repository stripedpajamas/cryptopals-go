package challenge10

import (
	"github.com/stripedpajamas/cryptopals/set1/challenge3"
	"github.com/stripedpajamas/cryptopals/set1/challenge7"
)

func CBCDecrypter(iv, ciphertext, key []byte) []byte {
	cLen := len(ciphertext)
	if cLen%16 != 0 {
		panic("Invalid ciphertext length")
	}
	if len(iv)%16 != 0 {
		panic("Invalid IV length")
	}
	if len(key)%16 != 0 {
		panic("Invalid key length")
	}

	var plaintext []byte

	// cycle through each block of ciphertext
	for i := 0; i < cLen; i += 16 {
		// take a block
		currentBlock := ciphertext[i : i+16]
		// decrypt it
		decrypted := challenge7.ECBDecrypter(currentBlock, key)
		// xor it with the IV
		xored := challenge3.XorBytes(iv, decrypted)
		// append to the plaintext
		plaintext = append(plaintext, xored...)

		// reset iv
		iv = currentBlock
	}

	return plaintext
}

func CBCEncrypter(iv, plaintext, key []byte) []byte {
	pLen := len(plaintext)
	if pLen%16 != 0 {
		panic("Invalid ciphertext length")
	}
	if len(iv)%16 != 0 {
		panic("Invalid IV length")
	}
	if len(key)%16 != 0 {
		panic("Invalid key length")
	}

	var ciphertext []byte

	// cycle through each block of ciphertext
	for i := 0; i < pLen; i += 16 {
		// take a block
		currentBlock := plaintext[i : i+16]
		// xor it with the IV
		xored := challenge3.XorBytes(iv, currentBlock)
		// decrypt it
		encrypted := challenge7.ECBEncrypter(xored, key)
		// append to the plaintext
		ciphertext = append(ciphertext, encrypted...)

		// reset iv
		iv = encrypted
	}

	return ciphertext
}
