package challenge52

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestCheapestHashEver(t *testing.T) {
	input := []byte("happiness is ever present in the sandwich")
	hash := CheapestHashEver(input, []byte("hi"))

	if !bytes.Equal(hash, []byte{203, 212}) {
		t.Fail()
	}
}

func TestCheapHash(t *testing.T) {
	input := []byte("happiness is ever present in the sandwich")
	hash := CheapHash(input, []byte("hi"))

	if !bytes.Equal(hash, []byte{88, 39, 89}) {
		t.Fail()
	}
}

func TestBeefyHash(t *testing.T) {
	input := []byte("happiness is ever present in the sandwich")
	hash := BeefyHash(input, []byte("hi"))

	if !bytes.Equal(hash, []byte{203, 212, 88, 39, 89}) {
		t.Fail()
	}
}

// func TestCheapestCollisionMachine(t *testing.T) {
// 	testInitialState := []byte("hi")
// 	initialState := make(chan []byte)
// 	collisions := make(chan Collision)
// 	go CheapestCollisionMachine(initialState, collisions)
// 	defer close(initialState)

// 	initialState <- testInitialState
// 	collision := <-collisions

// 	if !bytes.Equal(CheapestHashEver(collision.a, testInitialState), CheapestHashEver(collision.b, testInitialState)) {
// 		t.Fail()
// 	}
// }

func confirmGoodCollisions(collisions [][]byte, hashMap map[string][]byte) (error, int) {
	h := CheapestHashEver(collisions[0], []byte("hi"))
	for _, c := range collisions {
		hs := fmt.Sprintf("%0x", c)
		if _, found := hashMap[hs]; found {
			// already in map -- duplicate collision, doesn't count
			return errors.New("Duplicate collision"), 0
		}
		hashMap[hs] = c

		// confirm this hash has the same hash as the first hash
		h2 := CheapestHashEver(c, []byte("hi"))
		if !bytes.Equal(h, h2) {
			return errors.New("Collision didn't result in same hash"), 0
		}
	}
	// unique collisions = len(hashMap)
	return nil, len(hashMap)
}

func TestFindCheapestCollisions(t *testing.T) {
	collisionsWanted := make(chan int)
	collisionsFound := make(chan [][]byte)

	go FindCheapestCollisions(collisionsWanted, collisionsFound)
	defer close(collisionsWanted)

	// ask the finder for 3 multi collisions
	collisionsWanted <- 3
	collisions := <-collisionsFound

	testHashMap := make(map[string][]byte)
	err, length := confirmGoodCollisions(collisions, testHashMap)

	if err != nil {
		t.Error(err)
	}

	if length != 8 {
		t.Errorf("Wanted %d collisions, got %d", 8, length)
	}

	// generate some more collisions and make sure they aren't the same as the previous
	collisionsWanted <- 4
	collisions = <-collisionsFound
	err, length = confirmGoodCollisions(collisions, testHashMap)

	if err != nil {
		t.Error("Second round", err)
	}

	// 24 = 8 + 16 = first round (2^3) + second round (2^4)
	if length != 24 {
		t.Errorf("Second round: wanted %d collisions, got %d", 24, length)
	}
}

func TestFindMultiCollision(t *testing.T) {
	initialState := []byte("hi")
	collision := FindMultiCollision()
	cheapestHa := CheapestHashEver(collision.a, initialState)
	cheapestHb := CheapestHashEver(collision.b, initialState)
	cheapHa := CheapHash(collision.a, initialState)
	cheapHb := CheapHash(collision.b, initialState)
	if bytes.Equal(collision.a, collision.b) || !bytes.Equal(cheapHa, cheapHb) || !bytes.Equal(cheapestHa, cheapestHb) {
		t.Fail()
	}

	// and of course the whole point of this:
	if !bytes.Equal(BeefyHash(collision.a, initialState), BeefyHash(collision.b, initialState)) {
		t.Fail()
	}
}

var benchmarkResult *Collision

func BenchmarkFindMultiCollision(b *testing.B) {
	var collision *Collision
	for i := 0; i < b.N; i++ {
		collision = FindMultiCollision()
	}

	benchmarkResult = collision
}
