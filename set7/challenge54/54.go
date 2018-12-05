package challenge54

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/stripedpajamas/cryptopals/set7/challenge52"
	"github.com/stripedpajamas/cryptopals/set7/challenge53"
)

type Node struct {
	root  *Node
	data  []byte
	state []byte
}

func init() {
	rand.Seed(time.Now().Unix())
}

func GetRandomState() []byte {
	block := make([]byte, 3)
	rand.Read(block)
	return block
}

func GetGlueBlock(lastState []byte, nextStates map[string]int) (int, []byte) {
	// find a glue block such that the last state of the prefix
	// is the input state for some data D that produces a state in the entry map
	hashFunc := challenge52.CheapHashNoPad
	data := make([]byte, 16)
	for {
		rand.Read(data)
		hash := hashFunc(data, lastState)
		hashStr := fmt.Sprintf("%0x", hash)
		if idx, found := nextStates[hashStr]; found {
			return idx, data
		}
	}
}

// returns a hash that can be used for anything
func GetPredictionHash(length int, k int) ([]byte, func([]byte, []byte) []byte) {
	hashFunc := challenge52.CheapHashNoPad
	root, entryPoints := BuildDiamond(k)

	// we need to commit to a padding block as well
	// we will have k*16 bytes of intermediate blocks
	// plus 16 bytes for the glue block
	fullLength := length
	for fullLength%16 != 0 {
		fullLength++
	}
	fullLength += (k * 16) + 16
	padBlock := challenge52.Pad(make([]byte, fullLength))
	padBlock = padBlock[len(padBlock)-16:]

	predictionHash := hashFunc(padBlock, root.state)

	// build a quick map of the 2^k+1 - 2 entry points for quick lookups
	entryPointMap := make(map[string]int)
	for idx, entryPoint := range entryPoints {
		key := fmt.Sprintf("%0x", entryPoint.state)
		entryPointMap[key] = idx
	}

	// return a function to call when the prefix is known
	return predictionHash, func(prefix, initialState []byte) []byte {
		input := make([]byte, len(prefix))
		copy(input, prefix)
		// first pad out the prefix artificially with 0s
		// to get to the original length parameter
		for len(input) < length {
			input = append(input, 0)
		}
		// then pad out the prefix to be a block
		for len(input)%16 != 0 {
			input = append(input, 0)
		}

		entryPointIdx, glueBlock := GetGlueBlock(hashFunc(input, initialState), entryPointMap)
		var message []byte
		message = append(message, input...)
		message = append(message, glueBlock...)

		// append each data block until our final hash
		current := entryPoints[entryPointIdx]
		for current != nil {
			message = append(message, current.data...)
			current = current.root
		}

		return message
	}
}

// we are building a merkle tree from the bottom up
func BuildDiamond(k int) (*Node, []*Node) {
	// we start by generating 2^k initial states
	// and that forms our output array
	hashFunc := challenge52.CheapHashNoPad
	size := int(math.Exp2(float64(k)))
	output := make([]*Node, size)

	for idx := range output {
		output[idx] = new(Node)
		// generate random initial states
		output[idx].state = GetRandomState()
	}

	// now we pair up the nodes and find messages that collide
	// (the collision will produce a new state and therefore a new node)
	var populate func([]*Node) *Node
	populate = func(nodes []*Node) *Node {
		length := len(nodes)
		nextNodes := make([]*Node, length/2)
		nextIdx := 0
		for i := 0; i < length; i += 2 {
			pair := nodes[i : i+2]
			c := challenge53.FindCollision(hashFunc, pair[0].state, pair[1].state)
			pair[0].data = c.Short
			pair[1].data = c.Long
			root := new(Node)
			root.state = c.Hash
			pair[0].root = root
			pair[1].root = root
			nextNodes[nextIdx] = root
			nextIdx++
		}
		if len(nextNodes) == 1 {
			return nextNodes[0]
		}
		return populate(nextNodes)
	}

	root := populate(output)

	return root, output
}
