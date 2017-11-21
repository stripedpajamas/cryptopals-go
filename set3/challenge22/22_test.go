package challenge22

import (
	"testing"

	"github.com/stripedpajamas/cryptopals/set3/challenge21"
)

func TestFindSeed(t *testing.T) {
	// https://cryptopals.com/sets/3/challenges/22
	random := WaitThenRandom()
	foundSeed := FindSeed(random)

	MT := challenge21.NewMT19937()
	MT.Seed(foundSeed)

	if MT.Extract() != random {
		t.Fail()
	}
}
