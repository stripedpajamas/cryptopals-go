package challenge3

import (
	"strings"
	"bytes"
	"math"
)

type Processed struct {
	Key   byte
	Text  string
	Score float64
}

func ScoreString(s string) float64 {
	input := strings.ToLower(s)
	inputLen := float64(len(input))
	inputMap := map[int32]float64{}
	var finalScore float64

	// get letter counts
	for _, letter := range input {
		inputMap[letter] += 1
	}

	// get frequency of each letter as related to the length of the string
	// and compare to the standard
	for _, letter := range input {
		freq := inputMap[letter] / inputLen
		if LetterFrequency[letter] != 0 {
			finalScore += math.Abs(LetterFrequency[letter] - freq)
		} else {
			// this is not a normal english character so bump it up a lot
			finalScore += 10
		}
	}

	// generate an average
	finalScore /= inputLen

	return finalScore
}

func XorBytes(a, b []byte) []byte {
	aLen := len(a)
	if aLen != len(b) {
		panic("Inputs must have equal length")
	}

	var output = make([]byte, aLen)

	for i := 0; i < aLen; i++ {
		output[i] = a[i] ^ b[i]
	}

	return output
}

func CrackSingleKeyXOR(inputBytes []byte) *Processed {
	decodedInputs := map[byte]*Processed{}
	inputLen := len(inputBytes)

	var i byte = 0

	for ; i < 255; i++ {
		key := bytes.Repeat([]byte{i}, inputLen)
		xored := XorBytes(inputBytes, key)
		text := string(xored)
		decodedInputs[i] = &Processed{
			Key:   i,
			Text:  text,
			Score: ScoreString(text),
		}
	}

	// get the lowest score (the most like English)
	var topScoredKey byte
	for key, processedInput := range decodedInputs {
		if processedInput.Score < decodedInputs[topScoredKey].Score {
			topScoredKey = key
		}
	}
	return decodedInputs[topScoredKey]
}
