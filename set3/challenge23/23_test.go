package challenge23

import (
	"testing"

	"github.com/stripedpajamas/cryptopals/set3/challenge21"
)

func TestUntemper(t *testing.T) {
	for i := 0; i < 5; i++ {
		MT := challenge21.NewMT19937()
		MT.Seed(i)
		rando := MT.Extract()
		y := Untemper(rando)

		// apply the tempering process to see if we end up with the same number
		y = y ^ (y >> 11)
		y = y ^ ((y << 7) & 0x9D2C5680)
		y = y ^ ((y << 15) & 0xEFC60000)
		y = y ^ (y >> 18)

		if y != rando {
			t.Fail()
		}
	}
}

func TestCloneMT(t *testing.T) {
	// https://cryptopals.com/sets/3/challenges/23
	// pass in a seeded Mersenne Twister
	MT0 := challenge21.NewMT19937()
	MT0.Seed(6993)
	MTClone := CloneMT(MT0)

	// it should clone it and then produce the same numbers
	for i := 0; i < 5; i++ {
		if MTClone.Extract() != MT0.Extract() {
			t.Fail()
		}
	}
}
