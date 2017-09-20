package challenge4

import (
	"encoding/hex"
	"github.com/stripedpajamas/cryptopals/set1/challenge3"
)

type Identified struct {
	original  string
	processed *challenge3.Processed
}

func DetectSingleKeyXor(hexStrings []string) *Identified {
	inputLength := len(hexStrings)

	// create a container for the results
	processedStrings := make([]*Identified, inputLength)

	// make a channel to notify when we're done cracking all the schmutz
	doneCracking := make(chan bool, inputLength)

	// iterate through each encoded string and process it
	for i, hexString := range hexStrings {
		go func(i int, hexString string) {
			hexBytes, err := hex.DecodeString(hexString)
			if err != nil {
				panic(err)
			}
			cracked := challenge3.CrackSingleKeyXOR(hexBytes)
			processedStrings[i] = &Identified{
				original:  hexString,
				processed: cracked,
			}
			doneCracking <- true
		}(i, hexString)
	}

	// wait for all the cracking goroutines to finish
	for i := 0; i < inputLength; i++ {
		<-doneCracking
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
