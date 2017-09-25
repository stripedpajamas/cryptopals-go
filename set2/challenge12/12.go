package challenge12

import (
	"bytes"
	"github.com/stripedpajamas/cryptopals/set1/challenge7"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

var key []byte = challenge11.GenerateRandomKey()
var secret []byte = []byte{82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10}

func EncryptWithSecret(plaintext []byte) []byte {
	// as per the challenge, we have to append the secret to the plaintext
	// and pad before encrypting
	//testSecret := []byte{82, 111, 108, 108}
	plaintext = challenge9.Pad(append(plaintext, secret...), 16)
	//plaintext = challenge9.Pad(append(plaintext, testSecret...), 16)
	return challenge7.ECBEncrypter(plaintext, key)
}

func DetectBlockSize() int {
	// basically add bytes until output jumps
	blockSize := 0
	ciphertextLen := len(EncryptWithSecret([]byte("A")))
	for i := 2; blockSize < 1; i++ {
		currentLen := len(EncryptWithSecret(bytes.Repeat([]byte("A"), i)))
		if currentLen-ciphertextLen > 1 {
			blockSize = currentLen - ciphertextLen
		}
		ciphertextLen = currentLen
	}
	return blockSize
}

func DetectECB(blockSize int) bool {
	// add two identical blocks and confirm identical CTs
	payload := bytes.Repeat([]byte("A"), 2*blockSize)
	ciphertext := EncryptWithSecret(payload)
	for j := 0; j < len(ciphertext); j += blockSize {
		block := ciphertext[j : j+blockSize]
		if bytes.Count(ciphertext, block) > 1 {
			return true
		}
	}
	return false
}

func Crack() []byte {
	blockSize := DetectBlockSize()
	if DetectECB(blockSize) != true {
		panic("Not ECB")
	}
	secretLen := len(EncryptWithSecret([]byte{}))
	plaintext := make([]byte, secretLen)

	for currentBlockIdx := 0; currentBlockIdx < secretLen; currentBlockIdx += blockSize {
		for ptIdx, crackIdx := currentBlockIdx, 1; crackIdx <= blockSize; ptIdx, crackIdx = ptIdx+1, crackIdx+1 {
			target := currentBlockIdx + blockSize - 1
			payloadSize := blockSize - crackIdx
			payload := bytes.Repeat([]byte("A"), payloadSize)
			ciphertext := EncryptWithSecret(payload)

			// generate dictionary of possible last byte
			dic := make(map[byte][]byte, 255)
			// key is encrypted last byte
			// value is the byte that was encrypted
			var j byte = 0
			for ; j < 255; j++ {
				var dicPayload []byte
				prePayload := append(bytes.Repeat([]byte("A"), payloadSize), plaintext[:ptIdx]...)
				dicPayload = append(prePayload[:target], j)
				dicCiphertext := EncryptWithSecret(dicPayload)[currentBlockIdx : currentBlockIdx+blockSize]
				dic[j] = dicCiphertext
			}

			// now that dictionary has been created
			// iterate through it and look for a block match
			for decByte, encBytes := range dic {
				if bytes.Compare(ciphertext[currentBlockIdx:currentBlockIdx+blockSize], encBytes) == 0 {
					plaintext[ptIdx] = decByte
				}
			}
		}
	}
	return plaintext
}
