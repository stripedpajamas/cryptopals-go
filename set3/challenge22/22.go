package challenge22

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/stripedpajamas/cryptopals/set3/challenge21"
)

func WaitThenRandom(howlong int64) int {
	// get a random number
	randomTime, err := rand.Int(rand.Reader, big.NewInt(howlong))
	if err != nil {
		panic(err)
	}
	// sleep for that number of seconds
	time.Sleep(time.Duration(randomTime.Int64()) * time.Second)

	// get the current UNIX timestamp
	seed := time.Now().Unix()

	// use it to seed MT
	MT := challenge21.NewMT19937()
	MT.Seed(int(seed))

	// get another random number
	randomTime, err = rand.Int(rand.Reader, big.NewInt(200))
	if err != nil {
		panic(err)
	}

	// return the first number from MT
	return MT.Extract()
}

func FindSeed(random int) int {
	MT := challenge21.NewMT19937()
	seed := int(time.Now().Unix())
	MT.Seed(seed)
	myRandom := MT.Extract()

	// just go back in time by seconds until we find the right value
	for myRandom != random {
		seed--
		MT.Seed(seed)
		myRandom = MT.Extract()
	}

	return seed
}
