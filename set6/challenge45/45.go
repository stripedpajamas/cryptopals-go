package challenge45

import (
	"math/big"

	"github.com/stripedpajamas/cryptopals/set6/challenge43"
)

func MagicSignature(d *DSAAllowTampering, publicKey *big.Int) challenge43.MessageSignature {
	// apparently for any public key we can make a magic signature that will pass verification
	// r = ((y**z) % p) % q
	// s = r * modInv(z, q) mod q
	// for some arbitrary z
	one := big.NewInt(1)
	z := big.NewInt(123)

	r := new(big.Int).Exp(publicKey, z, d.P)
	r.Exp(r, one, d.Q)

	s := new(big.Int).ModInverse(z, d.Q)
	s.Mul(r, s)
	s.Exp(s, one, d.Q)

	return challenge43.MessageSignature{
		R: r,
		S: s,
	}
}
