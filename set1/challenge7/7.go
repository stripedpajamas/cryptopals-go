package challenge7

import "crypto/aes"

func ECBDecrypter(ciphertext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("Ciphertext too short")
	}

	// ECB mode always works in whole blocks
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("Ciphertext is not a multiple of the block size")
	}

	mode := NewECBDecrypter(block)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext
}

func ECBEncrypter(plaintext, key []byte) []byte {
	// Here we'll assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("Plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	mode := NewECBEncrypter(block)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}
