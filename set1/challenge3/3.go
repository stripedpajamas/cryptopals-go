package challenge3

import (
	"strings"
	"bytes"
	"math"
	"encoding/hex"
	"errors"
)

type Processed struct {
	Key	[]byte
	Text	string
	Score	float64
}

func ScoreString(s string) float64 {
	letterFrequency := map[int32]float64{
		32: 0.12802, // space character apparently slightly more popular than 'e'
		97: 0.08167,
		98: 0.01492,
		99: 0.02782,
		100: 0.04253,
		101: 0.12702,
		102: 0.02228,
		103: 0.02015,
		104: 0.06094,
		105: 0.06966,
		106: 0.00153,
		107: 0.00772,
		108: 0.04025,
		109: 0.02406,
		110: 0.06749,
		111: 0.07507,
		112: 0.01929,
		113: 0.00095,
		114: 0.05987,
		115: 0.06327,
		116: 0.09056,
		117: 0.02758,
		118: 0.00978,
		119: 0.02360,
		120: 0.00150,
		121: 0.01974,
		122: 0.00074,
	}

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
		if letterFrequency[letter] != 0 {
			finalScore += math.Abs(letterFrequency[letter] - freq)
		} else {
			// the letter was not found, so bump it up
			finalScore += 1
		}
	}

	// generate an average
	finalScore /= inputLen

	return finalScore
}

func XorBytes(a, b []byte) ([]byte, error) {
	aLen := len(a)
	if aLen != len(b) {
		return nil, errors.New("Inputs must have equal length")
	}

	var output = make([]byte, aLen)

	for i := 0; i < aLen; i++ {
		output[i] = a[i] ^ b[i]
	}

	return output, nil
}

func CrackSingleKeyXOR(hexString string) *Processed {
	decodedInputs := map[byte]*Processed{}
	inputBytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}

	inputLen := len(inputBytes)
	var i byte = 0

	for ; i < 255; i++ {
		key := bytes.Repeat([]byte{i}, inputLen)
		xored, err := XorBytes(inputBytes, key)
		if err != nil {
			panic(err)
		}
		text := string(xored)
		decodedInputs[i] = &Processed{
			Key: key,
			Text: text,
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