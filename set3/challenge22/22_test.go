package challenge22

import (
	"github.com/stripedpajamas/cryptopals/set3/challenge21"
	"testing"
)

func TestFindSeed(t *testing.T) {
	// https://cryptopals.com/sets/3/challenges/22
	random := WaitThenRandom()
	foundSeed := FindSeed(random)

	challenge21.Seed(foundSeed)

	if challenge21.Extract() != random {
		t.Fail()
	}
}
