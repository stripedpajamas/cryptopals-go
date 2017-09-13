package challenge4

import (
	"github.com/stripedpajamas/cryptopals/set1/challenge3"
)

type Identified struct {
	original  string
	processed *challenge3.Processed
}

func DetectSingleKeyXor(hexStrings []string) *Identified {
	// create a container for the results
	processedStrings := map[int]*Identified{}

	// iterate through each encoded string and process it
	for i, hexString := range hexStrings {
		cracked := challenge3.CrackSingleKeyXOR(hexString)
		processedStrings[i] = &Identified{
			original:  hexString,
			processed: cracked,
		}
	}

	// iterate through each of the processed strings and find the lowest score
	// which means least deviant from English
	var topScored int
	for i, processedInput := range processedStrings {
		if processedInput.processed.Score < processedStrings[topScored].processed.Score {
			topScored = i
		}
	}

	return processedStrings[topScored]
}
