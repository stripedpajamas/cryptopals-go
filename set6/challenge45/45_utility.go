package challenge45

import (
	"crypto/rand"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set6/challenge43"
)

// another DSA implementation that allows parameter tampering
type DSAAllowTampering struct {
	challenge43.DSA
}

func (d *DSAAllowTampering) SetG(g *big.Int) {
	d.G = g
}

func (d *DSAAllowTampering) Sign(messageHash []byte, privateKey *big.Int) challenge43.MessageSignature {
	// same as DSA.sign but allows zero values for r and k
	r := new(big.Int)
	s := new(big.Int)
	k := new(big.Int)

	// generate a per message k 1 < k < q
	tmp, err := rand.Int(rand.Reader, d.Q)
	if err != nil {
		panic(err)
	}
	tmp.Add(tmp, big.NewInt(2)) // to make sure 1 < k

	k = tmp
	r = new(big.Int).Exp(d.G, k, d.P)
	r.Exp(r, big.NewInt(1), d.Q)

	// calculate s = modInverse(k, q) * (H(m) + xr) mod q
	xr := new(big.Int).Mul(privateKey, r)
	hxr := new(big.Int).SetBytes(messageHash)
	hxr.Add(hxr, xr)

	mi := new(big.Int).ModInverse(k, d.Q)

	s = new(big.Int).Mul(mi, hxr)
	s.Exp(s, big.NewInt(1), d.Q)

	return challenge43.MessageSignature{
		R: r,
		S: s,
	}
}

func (d *DSAAllowTampering) Verify(messageHash []byte, sig challenge43.MessageSignature, publicKey *big.Int) bool {
	// verifies without checking to see if r > 0
	one := big.NewInt(1)

	w := new(big.Int).ModInverse(sig.S, d.Q)

	u1 := new(big.Int).SetBytes(messageHash)
	u1.Mul(u1, w)
	u1.Exp(u1, one, d.Q)

	u2 := new(big.Int).Mul(sig.R, w)
	u2.Exp(u2, one, d.Q)

	// v = (g^u1 * y^u2 mod p) mod q
	gu1 := new(big.Int).Exp(d.G, u1, d.P)
	gu2 := new(big.Int).Exp(publicKey, u2, d.P)
	gy := new(big.Int).Mul(gu1, gu2)
	gy.Exp(gy, one, d.P)

	v := new(big.Int).Exp(gy, one, d.Q)

	if v.Cmp(sig.R) == 0 {
		return true
	}
	return false
}
