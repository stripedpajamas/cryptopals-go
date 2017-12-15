package challenge43

import (
	"math/big"
)

func RecoverPrivate(d *DSA, messageHash []byte, sig MessageSignature, k *big.Int) *big.Int {
	// apparently if k is known, you can get to x (private key)
	// x = ((s * k) - H(m)) * modInv(r, q) mod q
	sk := new(big.Int).Mul(sig.S, k)
	hm := new(big.Int).SetBytes(messageHash)
	sk.Sub(sk, hm)

	mi := new(big.Int).ModInverse(sig.R, d.Q)

	x := new(big.Int).Mul(sk, mi)
	x.Exp(x, big.NewInt(1), d.Q)

	return x
}

func TryManyK(d *DSA, messageHash []byte, targetSig MessageSignature, publicKey *big.Int) *big.Int {
	// tries k's from 0 - 2^16 until it produces an x value that produces the target signature
	x := new(big.Int)

	for k := int64(0); k < 65536; k++ {
		// get x value for this k value
		kGuess := big.NewInt(k)
		x = RecoverPrivate(d, messageHash, targetSig, kGuess)
		mySig := d.Sign(messageHash, x)
		if d.Verify(messageHash, mySig, publicKey) {
			break
		}
	}

	return x
}
