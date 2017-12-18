package challenge45

import (
	"crypto/sha1"
	"math/big"
	"testing"

	"github.com/stripedpajamas/cryptopals/set6/challenge43"
)

func TestTampering(t *testing.T) {
	// set g to 0 and see what signatures look like
	dsa := DSAAllowTampering{}
	dsa.Initialize()
	myKey := dsa.GenerateUserKey()

	dsa.SetG(big.NewInt(0))

	m := sha1.Sum([]byte("hello world"))
	sig := dsa.Sign(m[:], myKey.Private)

	// now verify that signature
	verified := dsa.Verify(m[:], sig, myKey.Public)

	// the signature verifies
	if !verified {
		t.Fail()
	}

	// since g=0, literally anything will verify
	m = sha1.Sum([]byte("complete trash that you didn't sign"))
	sig = challenge43.MessageSignature{
		R: big.NewInt(0),
		S: big.NewInt(12345),
	}

	verified = dsa.Verify(m[:], sig, myKey.Public)

	if !verified {
		// lolz
		t.Fail()
	}
}

func TestMagicSignature(t *testing.T) {
	// set g = p+1
	dsa := DSAAllowTampering{}
	dsa.Initialize()
	myKey := dsa.GenerateUserKey()

	dsa.SetG(new(big.Int).Add(dsa.P, big.NewInt(1)))

	m1 := sha1.Sum([]byte("Hello, world"))
	m2 := sha1.Sum([]byte("Goodbye, world"))
	sig := MagicSignature(&dsa, myKey.Public)

	// now verify that signature
	verified1 := dsa.Verify(m1[:], sig, myKey.Public)
	verified2 := dsa.Verify(m2[:], sig, myKey.Public)

	if !verified1 || !verified2 {
		t.Fail()
	}
}
