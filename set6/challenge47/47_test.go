package challenge47

import (
	"bytes"
	"fmt"
	"testing"
)

func TestOracle(t *testing.T) {
	m := []byte("abcdefghijklmnopqrstu")
	c, err := rsa.EncryptWithPad(m, rsa.N, rsa.E)
	if err != nil {
		panic(err)
	}

	if !Oracle(c) {
		t.Fail()
	}
}

func TestBB98(t *testing.T) {
	m := []byte("kick it, CC")
	// c, err := rsa.EncryptWithPad(m, rsa.N, rsa.E)
	padded, err := rsa.Pad(m, rsa.N)
	c := rsa.Encrypt(padded, rsa.N, rsa.E)
	if err != nil {
		panic(err)
	}

	Verbose = false
	recovered := BB98(c, rsa.N, rsa.E, Oracle)
	recovered = append([]byte{0}, recovered...)

	if !bytes.Equal(recovered, padded) {
		fmt.Printf("Wanted:\t%x\nGot:\t%x\n", padded, recovered)
		t.Fail()
	}
}
