package challenge15

import (
	"bytes"
	"errors"
)

func RemoveValidPad(input []byte, blockSize int) ([]byte, error) {
	// same idea as Unpad in challenge9 but this one throws up if pad is bad
	for i := 1; i <= blockSize; i++ {
		pad := bytes.Repeat([]byte{byte(i)}, i)
		if bytes.HasSuffix(input, pad) {
			return input[:len(input)-i], nil
		}
	}
	return nil, errors.New("Invalid pad")
}
