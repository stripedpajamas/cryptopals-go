package challenge53

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stripedpajamas/cryptopals/set7/challenge52"
)

func TestFindCollisions(t *testing.T) {
	hashFunc := challenge52.CheapHashNoPad
	initialState := []byte{1, 2, 3}
	preInput := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	preHash := hashFunc(preInput, initialState)
	fails := 0
	for i := 0; i < 100; i++ {
		c := FindCollision(hashFunc, initialState, preHash)
		// theoretically... H(c.a) == H(preInput+c.b)
		hashOfA := hashFunc(c.Short, initialState)
		hashOfB := hashFunc(append(preInput, c.Long...), initialState)
		if !bytes.Equal(hashOfA, hashOfB) {
			fails++
		}
	}
	if fails > 0 {
		fmt.Printf("%d/100 fails\n", fails)
		t.Fail()
	}
}

func TestGetExpandables(t *testing.T) {
	hashFunc := challenge52.CheapHashNoPad
	initialState := []byte{1, 2, 3}
	k := 2
	expandables := GetExpandables(hashFunc, initialState, k)

	// basics: short and long hash to the same value
	hashOfA := hashFunc(expandables[0].Short, initialState)
	hashOfB := hashFunc(expandables[0].Long, initialState)
	if !bytes.Equal(hashOfA, hashOfB) {
		t.Fail()
	}

	// advanced: piecing together a longer message works
	// first message = short + next.long
	// second message = long + next.short
	a := append(expandables[0].Short, expandables[1].Long...)
	b := append(expandables[0].Long, expandables[1].Short...)
	hashOfA = hashFunc(a, initialState)
	hashOfB = hashFunc(b, initialState)
	if !bytes.Equal(hashOfA, hashOfB) {
		t.Fail()
	}
}

func TestForgeLongMessage(t *testing.T) {
	hashFunc := challenge52.CheapHashNoPad
	initialState := []byte{1, 2, 3}
	m := []byte("One of the basic yardsticks we use to judge a cryptographic hash function is its resistance to second preimage attacks. That means that if Igive you x and y such that H(x) = y, you should have a tough time finding x' such that H(x') = H(x) = y. How tough??")
	forgery := ForgeLongMessage(hashFunc, initialState, m)

	if len(m) != len(forgery) {
		t.Fail()
	}
	hashFunc = challenge52.CheapHash
	if !bytes.Equal(hashFunc(m, initialState), hashFunc(forgery, initialState)) {
		t.Fail()
	}
}
