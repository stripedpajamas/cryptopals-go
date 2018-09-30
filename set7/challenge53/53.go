package challenge53

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"time"
)

type Collision struct {
	Short []byte
	Long  []byte
	Hash  []byte
}

func FindCollision(hash func([]byte, []byte) []byte, initialState1, initialState2 []byte) *Collision {
	rand.Seed(time.Now().Unix())
	var collision *Collision
	hashesShort := make(map[string][]byte)
	hashesLong := make(map[string][]byte)
	for {
		short, long := make([]byte, 16), make([]byte, 16)
		rand.Read(short)
		rand.Read(long)
		shortHash, longHash := hash(short, initialState1), hash(long, initialState2)
		shortHashString, longHashString := fmt.Sprintf("%0x", shortHash), fmt.Sprintf("%0x", longHash)

		if previousLong, found := hashesLong[shortHashString]; found {
			// a's hash is already in b's map
			collision = &Collision{Short: short, Long: previousLong, Hash: shortHash}
			break
		} else if previousShort, found := hashesShort[longHashString]; found {
			// b's hash is already in a's map
			collision = &Collision{Short: previousShort, Long: long, Hash: longHash}
			break
		} else {
			// nothing in the map yet, so update it with the new values
			hashesShort[shortHashString] = short
			hashesLong[longHashString] = long
		}

		// might as well see if h(a) = h(b) while we're here
		if bytes.Equal(shortHash, longHash) {
			collision = &Collision{Short: short, Long: long, Hash: shortHash}
			break
		}
	}
	return collision
}

func GetExpandables(hash func([]byte, []byte) []byte, initialState []byte, k int) []*Collision {
	// starting from the hash function's initial state,
	// find a collision between a single-block message
	// and a message of 2^(k-1)+1 blocks.
	output := make([]*Collision, k)
	currentInitialState := initialState
	dummyTemplate := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 1; k-i >= 0; i++ {
		length := int(math.Exp2(float64(k)-float64(i))) + 1
		// generate a dummy block of length-1 blocks
		dummy := bytes.Repeat(dummyTemplate, length-1)
		dummyInitialState := hash(dummy, currentInitialState)
		output[i-1] = FindCollision(hash, currentInitialState, dummyInitialState)
		output[i-1].Long = append(dummy, output[i-1].Long...)
		currentInitialState = output[i-1].Hash
	}
	return output
}

func ForgeLongMessage(hash func([]byte, []byte) []byte, initialState []byte, m []byte) []byte {
	// generate an expandable message of length (k, k + 2^k - 1)
	// where 2^k = length in blocks of m
	k := int(math.Log2(math.Ceil(float64(len(m)) / 16)))
	expandables := GetExpandables(hash, initialState, k)

	// hash M and generate a map of intermediate hash states
	// to the block indices that they correspond to
	mHashBlocks := make(map[string]int)
	currentState := initialState
	for i := 0; i < len(m); i += 16 {
		var block []byte
		if i+16 >= len(m) {
			block = m[i:]
		} else {
			block = m[i : i+16]
		}
		h := hash(block, currentState)
		hs := fmt.Sprintf("%0x", h)
		mHashBlocks[hs] = i / 16
		currentState = h
	}
	// from your expandable message's final state,
	// find a single-block "bridge" to intermediate state in your map
	finalExpandableState := expandables[len(expandables)-1].Hash
	var bridge []byte
	var index int
	targetLength := len(m)
	for {
		bridge = make([]byte, 16)
		rand.Read(bridge)
		h := hash(bridge, finalExpandableState)
		hs := fmt.Sprintf("%0x", h)
		if idx, found := mHashBlocks[hs]; found {
			index = idx
			currentLength := len(m[(index+1)*16:]) + 16 //  (+16 for the bridge)
			neededBlocks := (targetLength - currentLength) / 16
			if neededBlocks < k {
				continue
			}
			upperBound := int(math.Exp2(float64(k))) + k - 1
			if neededBlocks > upperBound {
				continue
			}
			break
		}
	}

	// use your expandable message to generate a prefix
	// of the right length such that
	// len(prefix || bridge || M[i..]) = len(M)
	suffix := m[(index+1)*16:]
	forgery := append(bridge, suffix...)
	neededBlocks := (targetLength - len(forgery)) / 16

	// neededBlock's binary representation helps us choose the path
	var prefix []byte
	neededBlocks -= k // to get the bit string right
	for i := len(expandables) - 1; i >= 0; i-- {
		if neededBlocks&1 == 0 {
			// short
			prefix = append(expandables[i].Short, prefix...)
		} else {
			// long
			prefix = append(expandables[i].Long, prefix...)
		}
		neededBlocks >>= 1
	}
	forgery = append(prefix, forgery...)

	return forgery
}
