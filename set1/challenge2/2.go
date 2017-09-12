package challenge2

import (
	"errors"
	"encoding/hex"
)

func Xor(a, b string) (string, error) {
	if len(a) != len(b) {
		return "", errors.New("Inputs must have equal length")
	}
	aBytes, err := hex.DecodeString(a)
	if err != nil {
		return "", errors.New("Failed to decode hex string input A")
	}
	bBytes, err := hex.DecodeString(b)
	if err != nil {
		return "", errors.New("Failed to decode hex string input B")
	}

	aLen := len(aBytes)
	var output = make([]byte, aLen)

	for i := 0; i < aLen; i++ {
		output[i] = aBytes[i] ^ bBytes[i]
	}

	return hex.EncodeToString(output), nil
}
