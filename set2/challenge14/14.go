package challenge14

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set1/challenge7"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

var key []byte = challenge11.GenerateRandomKey()
var garbage []byte = GenerateGarbage()
var secret []byte = []byte{82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10}

func GenerateGarbage() []byte {
	// generate random length for garbage
	prependLen, err := rand.Int(rand.Reader, big.NewInt(32))
	if err != nil {
		panic(err)
	}

	// make the byte array
	garbage := make([]byte, prependLen.Int64())

	// read random bytes into it
	_, garbageErr := rand.Read(garbage)
	if garbageErr != nil {
		panic(garbageErr)
	}

	return garbage
}

func EncryptWithJunkySecret(plaintext []byte) []byte {
	// as per the challenge, we have to append the secret to the plaintext
	// and prepend a random amount of garbage bytes
	// and pad before encrypting
	prependedPlaintext := append(garbage, plaintext...)
	plaintext = challenge9.Pad(append(prependedPlaintext, secret...), 16)
	return challenge7.ECBEncrypter(plaintext, key)
}

func DupeIndex(ciphertext []byte) int {
	// returns the index of a duped block or -1 if no dupe was found
	for j := 0; j < len(ciphertext); j += 16 {
		block := ciphertext[j : j+16]
		idx := bytes.Index(ciphertext[j+16:], block)
		if idx >= 0 {
			// add the stuff we cut off of ciphertext for the search
			return idx + j + 16
		}
	}
	return -1
}

func Crack() []byte {
	// should find the secret using the same methods as challenge 12
	// but this time we have to locate where our payloads even fall in the ciphertext
	// to do this we will send a big payload that is bound to have at least 2 repeated blocks
	// .. for 16-byte blocks that should be 48-bytes
	//
	// then we need to subtract a byte until the dupe disappears -- when there is no dupe it
	// means that the trash bytes + our bytes + 1 is a multiple of the block size, making
	// the secret right where we want it to begin cracking

	// start by sending the 48x payload
	payload := bytes.Repeat([]byte("A"), 48)
	ciphertext := EncryptWithJunkySecret(payload)
	dupeIndex := DupeIndex(ciphertext)
	savedDupeIndex := dupeIndex

	// now we start subtracting until the dupe index returns -1
	for dupeIndex >= 0 {
		payload = payload[:len(payload)-1]
		ciphertext = EncryptWithJunkySecret(payload)
		dupeIndex = DupeIndex(ciphertext)
	}

	// when dupeIndex is -1 it means that the secret is in the perfect position for cracking
	// the saved dupe index is the index of the first duplicated block
	// so the 15 byte is the secret 1st byte
	// that's the idea at least
	payloadMarker := len(payload) + 1
	secretLen := len(ciphertext) - len(payload)
	plaintext := make([]byte, secretLen)

	for currentBlockIdx := savedDupeIndex; currentBlockIdx < len(ciphertext); currentBlockIdx += 16 {
		for ptIdx, crackIdx := currentBlockIdx-savedDupeIndex, 1; crackIdx <= 16 && ptIdx < secretLen; ptIdx, crackIdx = ptIdx+1, crackIdx+1 {
			payloadSize := payloadMarker - crackIdx
			payload := bytes.Repeat([]byte("A"), payloadSize)
			ciphertext = EncryptWithJunkySecret(payload)

			// generate dictionary of possible last byte
			dic := make(map[byte][]byte, 255)
			// key is encrypted last byte
			// value is the byte that was encrypted
			var j byte = 0
			for ; j < 255; j++ {
				var dicPayload []byte
				prePayload := append(bytes.Repeat([]byte("A"), payloadSize), plaintext[:ptIdx]...)
				dicPayload = append(prePayload, j)
				dicCiphertext := EncryptWithJunkySecret(dicPayload)[currentBlockIdx : currentBlockIdx+16]
				dic[j] = dicCiphertext
			}
			// now that dictionary has been created
			// iterate through it and look for a block match
			for decByte, encBytes := range dic {
				if bytes.Equal(ciphertext[currentBlockIdx:currentBlockIdx+16], encBytes) {
					plaintext[ptIdx] = decByte
				}
			}
		}
	}
	// there will be some garbage 0s at the end of plaintext because
	// the math to get the length of the plaintext array is optimistic :)
	// here we just clean it up
	return bytes.TrimRight(plaintext, string(0))
}
