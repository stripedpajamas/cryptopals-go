package challenge48

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stripedpajamas/cryptopals/set6/challenge47"
)

func TestBB98(t *testing.T) {
	ptB64 := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	pt, err := base64.StdEncoding.DecodeString(ptB64)
	if err != nil {
		panic(err)
	}

	padded, err := rsa.Pad(pt, rsa.N)
	c := rsa.Encrypt(padded, rsa.N, rsa.E)
	if err != nil {
		panic(err)
	}
	challenge47.Verbose = false
	recovered := challenge47.BB98(c, rsa.N, rsa.E, Oracle)
	recovered = append([]byte{0}, recovered...)

	if !bytes.Equal(recovered, padded) {
		fmt.Printf("Original:\t%x\nRecovered:\t%x\n", padded, recovered)
		t.Fail()
	}
}
