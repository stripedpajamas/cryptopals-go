package challenge22

import (
	"crypto/rand"
	"github.com/stripedpajamas/cryptopals/set3/challenge21"
	"math/big"
	"time"
)

func WaitThenRandom() int {
	// get a random number (I did 200 because I'm impatient)
	randomTime, err := rand.Int(rand.Reader, big.NewInt(200))
	if err != nil {
		panic(err)
	}
	// sleep for that number of seconds
	time.Sleep(time.Duration(randomTime.Int64()) * time.Second)

	// get the current UNIX timestamp
	seed := time.Now().Unix()

	// use it to seed MT
	challenge21.Seed(int(seed))

	// get another random number
	randomTime, err = rand.Int(rand.Reader, big.NewInt(200))
	if err != nil {
		panic(err)
	}

	// return the first number from MT
	return challenge21.Extract()
}

func FindSeed(random int) int {
	seed := int(time.Now().Unix())
	challenge21.Seed(seed)
	myRandom := challenge21.Extract()

	// just go back in time by seconds until we find the right value
	for myRandom != random {
		seed--
		challenge21.Seed(seed)
		myRandom = challenge21.Extract()
	}

	return seed
}
