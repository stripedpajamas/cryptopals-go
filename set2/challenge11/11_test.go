package challenge11

import (
	"bytes"
	"testing"
)

func TestGenerateRandomKey(t *testing.T) {
	key1 := GenerateRandomKey()
	key2 := GenerateRandomKey()

	if bytes.Compare(key1, key2) == 0 {
		t.Fail()
	}
}

func TestRandomlyPad(t *testing.T) {
	rp1 := RandomlyPad([]byte{1, 2, 3})
	rp2 := RandomlyPad([]byte{1, 2, 3})

	if bytes.Compare(rp1, rp2) == 0 {
		t.Fail()
	}
}

func TestRandomlyEncrypt(t *testing.T) {
	// http://cryptopals.com/sets/2/challenges/11
	c11input := `
	Write it on your heart that every day is the best day in the year.
	He is rich who owns the day, and no one owns the day who allows it
	to be invaded with fret and anxiety. Finish every day and be done
	with it. You have done what you could. Some blunders and absurdities,
	no doubt crept in. Forget them as soon as you can, tomorrow is a new
	day; begin it well and serenely, with too high a spirit to be
	cumbered with your old nonsense. This new day is too dear, with its
	hopes and invitations, to waste a moment on the yesterdays.`

	c11output1 := RandomlyEncrypt([]byte(c11input))
	c11output2 := RandomlyEncrypt([]byte(c11input))

	if bytes.Compare(c11output1.ciphertext, c11output2.ciphertext) == 0 {
		t.Fail()
	}
}

func TestDetectMode(t *testing.T) {
	c11input := "Some blunders and absurdities no doubt crept in Some blunders and absurdities, no doubt crept in"

	c11output := RandomlyEncrypt([]byte(c11input))

	if DetectMode(c11output.ciphertext) != c11output.mode {
		t.Fail()
	}
}
