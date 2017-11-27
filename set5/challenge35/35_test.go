package challenge35

import (
	"bytes"
	"math/big"
	"testing"
)

func TestAliceAndBob(t *testing.T) {
	msg := []byte("hello bob. i think you should by amazon stock -a")
	vals := AliceAndBob([]byte{5}, SendNormal)

	if !bytes.Equal(vals[0], vals[1]) {
		t.Fail()
	}
	if !bytes.Equal(vals[0], msg) {
		t.Fail()
	}
	ResetEveStash()

	// this is testing with g value set to 1
	vals = AliceAndBob([]byte{1}, SendThroughEve)

	// first confirm alice and bob can't tell the difference
	if !bytes.Equal(vals[0], vals[1]) || !bytes.Equal(vals[0], msg) {
		t.Fail()
	}

	// then see if eve knows things
	if !bytes.Equal(eveStash.DiscoveredPT[0], eveStash.DiscoveredPT[1]) {
		t.Error("Didn't work with 1")
	}
	if !bytes.Equal(eveStash.DiscoveredPT[0], msg) {
		t.Error("Didn't work with 1 (second check)")
	}
	ResetEveStash()

	// this is testing with g value set to p-1
	pBytes := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0xf, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x2, 0x4e, 0x8, 0x8a, 0x67, 0xcc, 0x74, 0x2, 0xb, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x8, 0x79, 0x8e, 0x34, 0x4, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0xa, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0xb, 0xff, 0x5c, 0xb6, 0xf4, 0x6, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x0, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x5, 0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x7, 0x70, 0x96, 0x96, 0x6d, 0x67, 0xc, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x4, 0xf1, 0x74, 0x6c, 0x8, 0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	pMinusOne := new(big.Int)
	pMinusOne.SetBytes(pBytes)
	pMinusOne.Sub(pMinusOne, big.NewInt(1))
	vals = AliceAndBob(pMinusOne.Bytes(), SendThroughEve)

	// first confirm alice and bob can't tell the difference
	if !bytes.Equal(vals[0], vals[1]) || !bytes.Equal(vals[0], msg) {
		t.Fail()
	}

	// then see if eve knows things
	if !bytes.Equal(eveStash.DiscoveredPT[0], eveStash.DiscoveredPT[1]) {
		t.Error("Didn't work with p-1")
	}
	if !bytes.Equal(eveStash.DiscoveredPT[0], msg) {
		t.Error("Didn't work with p-1 (second check)")
	}
	ResetEveStash()

	// this is testing with g value set to p
	vals = AliceAndBob(pBytes, SendThroughEve)

	// first confirm alice and bob can't tell the difference
	if !bytes.Equal(vals[0], vals[1]) || !bytes.Equal(vals[0], msg) {
		t.Fail()
	}

	// then see if eve knows things
	if !bytes.Equal(eveStash.DiscoveredPT[0], eveStash.DiscoveredPT[1]) {
		t.Error("Didn't work with p")
	}
	if !bytes.Equal(eveStash.DiscoveredPT[0], msg) {
		t.Error("Didn't work with p (second check")
	}
	ResetEveStash()
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