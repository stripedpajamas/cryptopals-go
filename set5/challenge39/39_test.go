package challenge39

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"
)

var rsa RSA = RSA{}

func init() {
	rsa.Initialize(1024)
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

func TestRSA_Pad(t *testing.T) {
	m := []byte("abcdefg")

	tmp := RSA{}
	tmp.Initialize(256)
	padded, err := tmp.Pad(m, tmp.N)
	if err != nil {
		panic(err)
	}

	if padded[0] != 0 || padded[1] != 2 || padded[24] != 0 {
		t.Fail()
	}
	if !bytes.Equal(padded[len(padded)-7:], m) {
		t.Fail()
	}
}
