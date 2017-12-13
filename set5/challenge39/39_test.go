package challenge39

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"
)

var rsa RSA = RSA{}

func init() {
	rsa.Initialize()
}

func TestRSA(t *testing.T) {
	pt := []byte("hello world")

	enc := rsa.Encrypt(pt, rsa.N, rsa.E)
	dec := rsa.Decrypt(enc)

	if !bytes.Equal(dec, pt) {
		t.Fail()
	}
}

func TestRSA_Sign(t *testing.T) {
	// create signature
	pt := []byte("potatoes will prevail")
	ptHash := sha256.Sum256(pt)

	sig := rsa.Sign(ptHash[:], crypto.SHA256)

	// verify signature
	verified := rsa.VerifySignature(rsa.N, rsa.E, ptHash[:], sig, crypto.SHA256)

	if !verified {
		t.Fail()
	}
}
