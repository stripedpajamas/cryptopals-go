package challenge54

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stripedpajamas/cryptopals/set7/challenge52"
)

func printNode(n *Node) {
	fmt.Println("\t", "data:", n.data, "\n\t\tstate:", n.state)
	if n.root != nil {
		printNode(n.root)
	}
}

func TestGetPredictionHash(t *testing.T) {
	// assume our prefix (when known) will have length <= 20
	prediction, solver := GetPredictionHash(20, 8)

	// assume we now know the prefix and want data that
	// will hash to our prediction hash that starts with our prefix
	result := solver([]byte("hello world"), []byte{})
	if !bytes.Contains(result, []byte("hello world")) {
		t.Fail()
	}

	// someone else takes our result and hashes it
	hashedResult := challenge52.CheapHash(result, []byte{})

	if !bytes.Equal(prediction, hashedResult) {
		t.Fail()
	}
}

func TestBuildDiamond(t *testing.T) {
	_, output := BuildDiamond(3)

	// diamond has a base of 2^k
	if len(output) != 8 {
		t.Fail()
	}
}
