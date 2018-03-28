package challenge52

import (
	"bytes"
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

func TestCheapestCollisionMachine(t *testing.T) {
	initialState := []byte("hi")
	collision := CheapestCollisionMachine(initialState)
	if !bytes.Equal(CheapestHashEver(collision.a, initialState), CheapestHashEver(collision.b, initialState)) {
		t.Fail()
	}
}

func TestFindCheapestCollisions(t *testing.T) {
	hashMap := make(map[string][]byte)
	collisions := FindCheapestCollisions(3)
	for _, c := range collisions {
		hs := fmt.Sprintf("%0x", c)
		if _, found := hashMap[hs]; found {
			// already in map -- duplicate collision, doesn't count
			t.Fail()
		} else {
			hashMap[hs] = c
		}
	}
	if len(collisions) != 8 || len(hashMap) != 8 {
		t.Fail()
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
