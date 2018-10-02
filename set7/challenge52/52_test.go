package challenge52

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPad(t *testing.T) {
	input := []byte("yellow submarin")
	output := Pad(input)

	if len(output)%16 != 0 {
		t.Fail()
	}
}

func TestCheapestHashEver(t *testing.T) {
	input := []byte("happiness is ever present in the sandwich")
	hash := CheapestHashEver(input, []byte("hi"))

	if !bytes.Equal(hash, []byte{81, 114}) {
		t.Fail()
	}
}

func TestCheapHash(t *testing.T) {
	input := []byte("happiness is ever present in the sandwich")
	hash := CheapHash(input, []byte("hi"))

	if !bytes.Equal(hash, []byte{163, 199, 191}) {
		t.Fail()
	}
}

func TestBeefyHash(t *testing.T) {
	input := []byte("happiness is ever present in the sandwich")
	hash := BeefyHash(input, []byte("hi"))

	if !bytes.Equal(hash, []byte{81, 114, 163, 199, 191}) {
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
	inputMap := make(map[string][]byte)
	initialState := []byte("hi")
	collisions := FindCheapestCollisions(3, initialState)
	firstHash := CheapestHashEver(collisions[0], initialState)
	for _, c := range collisions {
		// all collisions hash to the same value
		h := CheapestHashEver(c, initialState)
		if !bytes.Equal(h, firstHash) {
			t.Fail()
		}

		// no duplicate collisions
		str := fmt.Sprintf("%0x", c)
		if _, found := inputMap[str]; found {
			t.Fail()
		} else {
			inputMap[str] = c
		}
	}
	if len(collisions) != 8 || len(inputMap) != 8 {
		t.Fail()
	}
}

func TestFindMultiCollision(t *testing.T) {
	initialState := []byte("hi")
	collision := FindMultiCollision(initialState)
	if !bytes.Equal(BeefyHash(collision.a, initialState), BeefyHash(collision.b, initialState)) {
		t.Fail()
	}
}
