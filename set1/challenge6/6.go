package challenge6

import (
	"math"
	"math/bits"
	"sort"

	"github.com/stripedpajamas/cryptopals/set1/challenge3"
	"github.com/stripedpajamas/cryptopals/set1/challenge5"
)

type Cracked struct {
	key  []byte
	text string
}

type Processed struct {
	Key   []byte
	Text  string
	Score float64
}

// map of key lengths to their hamming distance result
type KeyLengthGuess struct {
	keyLength       int
	hammingDistance float64
}

func HammingDistance(a, b []byte) int {
	// the hamming distance is the xor of the two byte arrays
	// added up (111000 = 1+1+1+0+0+0)
	xor := challenge3.XorBytes(a, b)
	total := 0

	for _, xorByte := range xor {
		total += bits.OnesCount8(xorByte)
	}

	return total
}

type ByHammingDistance []KeyLengthGuess

func (a ByHammingDistance) Len() int           { return len(a) }
func (a ByHammingDistance) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByHammingDistance) Less(i, j int) bool { return a[i].hammingDistance < a[j].hammingDistance }

type ByScore []Processed

func (a ByScore) Len() int           { return len(a) }
func (a ByScore) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByScore) Less(i, j int) bool { return a[i].Score < a[j].Score }

func CrackRepeatingKeyXor(cipherBytes []byte) Cracked {
	cipherLength := len(cipherBytes)

	possibleKeyLengths := make([]KeyLengthGuess, 39)

	// try key sizes up to 40chars
	// take two chunks of guess length and find the normalized hamming distance
	for i := 2; i <= 40; i++ {
		firstChunk := cipherBytes[0:i]
		secondChunk := cipherBytes[i : i*2]
		thirdChunk := cipherBytes[i*2 : i*3]
		fourthChunk := cipherBytes[i*3 : i*4]
		hDistance1 := float64(HammingDistance(firstChunk, secondChunk)) / float64(i)
		hDistance2 := float64(HammingDistance(secondChunk, thirdChunk)) / float64(i)
		hDistance3 := float64(HammingDistance(thirdChunk, fourthChunk)) / float64(i)
		hDistance4 := float64(HammingDistance(firstChunk, thirdChunk)) / float64(i)
		hDistance5 := float64(HammingDistance(secondChunk, fourthChunk)) / float64(i)
		average := (hDistance1 + hDistance2 + hDistance3 + hDistance4 + hDistance5) / 5
		possibleKeyLengths[i-2] = KeyLengthGuess{keyLength: i, hammingDistance: average}
	}

	sort.Sort(ByHammingDistance(possibleKeyLengths))

	// grab the top five
	probableKeyLengths := possibleKeyLengths[:3]

	// make a container for all the processed ciphertexts for each key length guess
	allProcessed := make([]Processed, 3)

	// for each probable key length, create blocks of ciphertext
	// such that block 1 has all the 1st bytes of each key-sized block
	// and block 2 has all the 2nd bytes of each key-sized block, etc
	for g, guess := range probableKeyLengths {
		// we make an array of byte arrays
		// the array of byte arrays has a length of the guessed key length
		transposedBlocks := make([][]byte, guess.keyLength)

		// each block will be ~the cipher text length / guessed key length
		tBlockSize := int(math.Ceil(float64(cipherLength) / float64(guess.keyLength)))

		// we loop through the ciphertext and take every letter
		// at index multiple of guessed keylength and stick into
		// the byte array at index j
		for tSliceIdx, _ := range transposedBlocks {
			transposedBlocks[tSliceIdx] = make([]byte, tBlockSize)
			tByteIdx := 0
			for i := tSliceIdx; tByteIdx < tBlockSize && i < cipherLength; tByteIdx, i = tByteIdx+1, i+guess.keyLength {
				transposedBlocks[tSliceIdx][tByteIdx] = cipherBytes[i]
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

		// now generate the plaintext with this key and score it for later
		possiblePlaintext := string(challenge5.RepeatingKeyXOR(cipherBytes, recoveredKey))
		allProcessed[g] = Processed{
			Key:   recoveredKey,
			Text:  possiblePlaintext,
			Score: challenge3.ScoreString(possiblePlaintext),
		}
	}

	sort.Sort(ByScore(allProcessed))

	// the first element will be the one with the highest score
	return Cracked{
		key:  allProcessed[0].Key,
		text: allProcessed[0].Text,
	}
}
