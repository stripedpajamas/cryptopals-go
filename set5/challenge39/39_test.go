package challenge39

import (
	"bytes"
	"testing"
)

func TestRSA(t *testing.T) {
	rsa := RSA{}
	rsa.Initialize()

	pt := []byte("hello world")

	enc := rsa.Encrypt(pt, rsa.N, rsa.E)
	dec := rsa.Decrypt(enc)

	if !bytes.Equal(dec, pt) {
		t.Fail()
	}
}
