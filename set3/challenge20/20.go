package challenge20

import (
	"bytes"
	"encoding/base64"
	"github.com/stripedpajamas/cryptopals/set1/challenge3"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set3/challenge18"
	"io/ioutil"
)

// get a random key and a fixed nonce of 0
var key []byte = challenge11.GenerateRandomKey()
var nonce []byte = []byte{0, 0, 0, 0, 0, 0, 0, 0}

var ptArray [][]byte
var ctArray [][]byte

func init() {
	processPT()
}

func processPT() {
	// get the plaintexts from the file and load them into an array
	plaintextB64Bytes, err := ioutil.ReadFile("20.txt")
	if err != nil {
		panic(err)
	}

	pt64Array := bytes.Split(plaintextB64Bytes, []byte{10})
	ptArray = make([][]byte, len(pt64Array))

	for i, pt64 := range pt64Array {
		ptArray[i] = make([]byte, len(pt64))
		bytesWritten, err := base64.StdEncoding.Decode(ptArray[i], pt64)
		if err != nil {
			panic(err)
		}
		ptArray[i] = ptArray[i][:bytesWritten]
	}

	// encrypt everything
	ctArray = make([][]byte, len(ptArray))
	for i, pt := range ptArray {
		ctArray[i] = challenge18.CTR(pt, key, nonce)
	}
}

func Crack() [][]byte {
	// first step is to truncate the ciphertexts to the length of the shortest
	shortestCtIdx := 0

	for i, ct := range ctArray {
		if len(ct) < len(ctArray[shortestCtIdx]) {
			shortestCtIdx = i
		}
	}

	shortestCtLen := len(ctArray[shortestCtIdx])

	ctArrayCopy := make([][]byte, len(ctArray))
	copy(ctArrayCopy, ctArray)

	for i, _ := range ctArrayCopy {
		ctArrayCopy[i] = ctArrayCopy[i][:shortestCtLen]
	}

	// now we apply the repeating key xor crack with keysize fixed to shortestCtLen

	// we make an array of byte arrays
	// the array of byte arrays has a length of the guessed key length
	transposedBlocks := make([][]byte, shortestCtLen)

	// each block will be the length of the ctArray
	tBlockSize := len(ctArrayCopy)

	// we loop through the ciphertext and take every byte
	// at index multiple of keylength and stick into
	// a new byte array
	for tSliceIdx, _ := range transposedBlocks {
		transposedBlocks[tSliceIdx] = make([]byte, tBlockSize)
		for tByteIdx := 0; tByteIdx < tBlockSize; tByteIdx++ {
			transposedBlocks[tSliceIdx][tByteIdx] = ctArrayCopy[tByteIdx][tSliceIdx]
		}
	}

	// now that transposedBlocks is populated, attempt single-key xor crack
	// on each block to put together the key one byte at a time
	recoveredKey := []byte{}
	for _, block := range transposedBlocks {
		// add just the first byte of each cracked single-key block so we can create
		// the proper key with it
		recoveredKey = append(recoveredKey, challenge3.CrackSingleKeyXOR(block).Key)
	}

	// now generate the plaintexts with this key
	crackedArray := make([][]byte, len(ctArrayCopy))
	for i, ct := range ctArrayCopy {
		crackedArray[i] = make([]byte, len(ct))
		crackedArray[i] = challenge3.XorBytes(ct, recoveredKey)
	}

	return crackedArray
}
