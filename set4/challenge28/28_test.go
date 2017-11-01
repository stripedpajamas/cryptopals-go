package challenge28

import (
	"bytes"
	"testing"
)

func TestSHA1MAC(t *testing.T) {
	// https://cryptopals.com/sets/4/challenges/28
	msg := []byte("teaspoons and trash cans")
	key := []byte("at least msg tastes good")

	output := []byte{166, 64, 75, 13, 138, 240, 155, 123, 86, 53, 206, 225, 112, 108, 250, 233, 165, 216, 149, 37}
	// a6404b0d8af09b7b5635cee1706cfae9a5d89525

	emptyKeyedMac := SHA1MAC([]byte(""), msg)
	if !bytes.Equal(emptyKeyedMac[0:20], output) {
		t.Fail()
	}

	output = []byte{29, 20, 82, 165, 58, 219, 172, 205, 6, 27, 40, 208, 170, 51, 178, 183, 238, 15, 5, 15}
	// 1d1452a53adbaccd061b28d0aa33b2b7ee0f050f

	keyedMac := SHA1MAC(key, msg)
	if !bytes.Equal(keyedMac[0:20], output) {
		t.Fail()
	}

	// confirm that we can't tamper with a message
	msg = []byte("hello")
	key = []byte("world")
	sum := SHA1MAC(key, msg)

	msg = []byte("hellp")
	sum2 := SHA1MAC(key, msg)

	if bytes.Equal(sum[0:20], sum2[0:20]) {
		t.Fail()
	}
}
