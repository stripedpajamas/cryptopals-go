package challenge46

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestOracle(t *testing.T) {
	oddPT := []byte("hi") // 110100001101001
	ct := rsa.Encrypt(oddPT, rsa.N, rsa.E)

	if Oracle(ct) {
		t.Fail()
	}

	evenPT := []byte("hj") // 110100001101010
	ct = rsa.Encrypt(evenPT, rsa.N, rsa.E)

	if !Oracle(ct) {
		t.Fail()
	}
}

func TestFindPlaintext(t *testing.T) {
	ptB64 := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	pt, err := base64.StdEncoding.DecodeString(ptB64)
	if err != nil {
		panic(err)
	}

	ct := rsa.Encrypt(pt, rsa.N, rsa.E)
	recovered := FindPlaintext(ct, rsa.N, rsa.E)

	if !bytes.Equal(recovered, pt) {
		fmt.Println("Recovered PT not equal to original PT")
		t.Fail()
	}

	fmt.Println(string(recovered))
}
