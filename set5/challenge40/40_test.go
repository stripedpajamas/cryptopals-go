package challenge40

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
)

func TestCubeRoot(t *testing.T) {
	tmp := big.NewInt(27)
	if CubeRoot(tmp).Cmp(big.NewInt(3)) != 0 {
		t.Fail()
	}
}

func TestDiscoverPlaintext(t *testing.T) {
	// make 3 RSA instances
	a := challenge39.RSA{}
	b := challenge39.RSA{}
	c := challenge39.RSA{}

	a.Initialize()
	b.Initialize()
	c.Initialize()

	pt := []byte("There is one mind common to all individual men. Every man is an inlet to the same and to all of the same.")
	m := new(big.Int).SetBytes(pt)

	c0 := new(big.Int).SetBytes(a.Encrypt(m.Bytes(), a.N, a.E))
	c1 := new(big.Int).SetBytes(b.Encrypt(m.Bytes(), b.N, b.E))
	c2 := new(big.Int).SetBytes(c.Encrypt(m.Bytes(), c.N, c.E))

	result := DiscoverPlaintext(c0, c1, c2, a.N, b.N, c.N)

	if !bytes.Equal(result.Bytes(), pt) {
		t.Fail()
	}
}
