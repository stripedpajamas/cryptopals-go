package challenge9

import "bytes"

func Pad(input []byte, blockSize int) []byte {
	inputLen := len(input)
	diff := blockSize - (inputLen % blockSize)
	var pad []byte

	// if input is already a multiple of blocksize
	// append a full block
	if diff == 0 {
		pad = bytes.Repeat([]byte{byte(blockSize)}, blockSize)
	} else {
		// otherwise pad the number of needed bytes
		pad = bytes.Repeat([]byte{byte(diff)}, diff)
	}

	return append(input, pad...)
}
