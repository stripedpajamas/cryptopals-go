package challenge5

import (
	"encoding/hex"
)

func RepeatingKeyXORStrings(plaintext, key string) string {
	plaintextBytes, keyBytes := []byte(plaintext), []byte(key)

	output := RepeatingKeyXOR(plaintextBytes, keyBytes)

	return hex.EncodeToString(output)
}

func RepeatingKeyXOR(plaintext, key []byte) []byte {
	keyLen := len(key)

	output := make([]byte, len(plaintext))

	for i, ptByte := range plaintext {
		output[i] = ptByte ^ key[i%keyLen]
	}

	return output
}
