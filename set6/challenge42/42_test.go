package challenge42

import (
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
)

func TestForgeSignature(t *testing.T) {
	// just for use of the public exponents
	rsa := challenge39.RSA{}
	rsa.Initialize()

	input := []byte("hi mom")
	sig := ForgeSignature(input, rsa.N)

	inputHash := sha256.Sum256(input)
	verified := rsa.VerifySignature(rsa.N, rsa.E, inputHash[:], sig, crypto.SHA256)
	if !verified {
		t.Fail()
	}
}
