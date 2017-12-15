package challenge43

import (
	"crypto/rand"
	"math/big"
)

type DSA struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

type UserKey struct {
	Private *big.Int
	Public  *big.Int
}

type MessageSignature struct {
	R *big.Int
	S *big.Int
}

func (d *DSA) Initialize() {
	d.P = new(big.Int).SetBytes(P)
	d.Q = new(big.Int).SetBytes(Q)
	d.G = new(big.Int).SetBytes(G)
}

func (d *DSA) GenerateUserKey() UserKey {
	// generate random x, 0 < x < q
	x, err := rand.Int(rand.Reader, d.Q)
	if err != nil {
		panic(err)
	}

	// calculate public key y = g^x mod p
	y := new(big.Int).Exp(d.G, x, d.P)
	return UserKey{
		Private: x,
		Public:  y,
	}
}

func (d *DSA) Sign(messageHash []byte, privateKey *big.Int) MessageSignature {
	r := new(big.Int)
	s := new(big.Int)
	k := new(big.Int)

	zero := big.NewInt(0)

	for s.Cmp(zero) == 0 {
		for r.Cmp(zero) == 0 {
			// generate a per message k 1 < k < q
			tmp, err := rand.Int(rand.Reader, d.Q)
			if err != nil {
				panic(err)
			}
			tmp.Add(tmp, big.NewInt(2)) // to make sure 1 < k

			k = tmp
			r = new(big.Int).Exp(d.G, k, d.P)
			r.Exp(r, big.NewInt(1), d.Q)
		}

		// calculate s = modInverse(k, q) * (H(m) + xr) mod q
		xr := new(big.Int).Mul(privateKey, r)
		hxr := new(big.Int).SetBytes(messageHash)
		hxr.Add(hxr, xr)

		mi := new(big.Int).ModInverse(k, d.Q)

		s = new(big.Int).Mul(mi, hxr)
		s.Exp(s, big.NewInt(1), d.Q)
	}
	return MessageSignature{
		r,
		s,
	}
}

func (d *DSA) Verify(messageHash []byte, sig MessageSignature, publicKey *big.Int) bool {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	// reject if 0 < r < q and 0 < s < q is not true
	if zero.Cmp(sig.R) != -1 || d.Q.Cmp(sig.R) != 1 || zero.Cmp(sig.S) != -1 || d.Q.Cmp(sig.S) != 1 {
		return false
	}

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
