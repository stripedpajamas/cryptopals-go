package challenge8

import (
	"bytes"
)

func DetectECB(ciphertexts [][]byte) [][]byte {
	// basically just check each byte array for duplicates of a 16-byte block
	ecbFoundIdxs := map[int]bool{}

	for idx, ciphertext := range ciphertexts {
		// find any ciphertexts that have repeated blocks
		for j := 0; j < len(ciphertext); j += 16 {
			block := ciphertext[j:j+16]
			if bytes.Count(ciphertext, block) > 1 {
				ecbFoundIdxs[idx] = true
			}
		}

	}
	ecbFound := make([][]byte, len(ecbFoundIdxs))
	// compile list based on index
	i := 0
	for foundIdx, _ := range ecbFoundIdxs {
		ecbFound[i] = ciphertexts[foundIdx]
		i++
	}
	return ecbFound
}
