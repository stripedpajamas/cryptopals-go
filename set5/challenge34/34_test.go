package challenge34

import (
	"bytes"
	"testing"
)

func TestAliceAndBob(t *testing.T) {
	vals := AliceAndBob(SendNormal)
	msg := []byte("hello bob. i think you should by amazon stock -a")

	if !bytes.Equal(vals[0], vals[1]) {
		t.Fail()
	}
	if !bytes.Equal(vals[0], msg) {
		t.Fail()
	}
}

func TestSendNormal(t *testing.T) {
	// this function doesn't do anything
	payload := [][]byte{
		[]byte{1, 2, 3},
		[]byte{4, 5, 6},
	}
	received := SendNormal(payload)

	for i, b := range payload {
		if !bytes.Equal(b, received[i]) {
			t.Fail()
		}
	}
}

func TestAliceAndBob2(t *testing.T) {
	vals := AliceAndBob(SendThroughEve)
	msg := []byte("hello bob. i think you should by amazon stock -a")

	// first confirm alice and bob can't tell the difference
	if !bytes.Equal(vals[0], vals[1]) || !bytes.Equal(vals[0], msg) {
		t.Fail()
	}

	// then see if eve knows things
	if !bytes.Equal(eveStash.DiscoveredPT[0], eveStash.DiscoveredPT[1]) {
		t.Fail()
	}
	if !bytes.Equal(eveStash.DiscoveredPT[0], msg) {
		t.Fail()
	}
}
