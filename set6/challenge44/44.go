package challenge44

import (
	"crypto/sha1"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set6/challenge43"
)

func RecoverK(d *challenge43.DSA, msgs [][]byte, sigs []challenge43.MessageSignature) *big.Int {
	// any two messages with the same r value in their signature means they
	// both were signed with the same k value

	// make a map of R values to their idx in our list of msgs/sigs
	sigMap := make(map[string]int)
	var m1, m2 []byte
	var s1, s2 challenge43.MessageSignature

	for idx, sig := range sigs {
		if _, ok := sigMap[sig.R.String()]; ok {
			m1 = msgs[sigMap[sig.R.String()]]
			m2 = msgs[idx]
			s1 = sigs[sigMap[sig.R.String()]]
			s2 = sigs[idx]
		} else {
			sigMap[sig.R.String()] = idx
		}
	}

	one := big.NewInt(1)
	// now that we have a reused k, we can solve for it
	// k = (mh1-mh2) * modInv((s1-s2), q) mod q
	mhash1, mhash2 := sha1.Sum(m1), sha1.Sum(m2)
	mh1 := new(big.Int).SetBytes(mhash1[:])
	mh2 := new(big.Int).SetBytes(mhash2[:])

	// get those hashes mod Q for convenience
	mh1.Exp(mh1, one, d.Q)
	mh2.Exp(mh2, one, d.Q)

	tmp := new(big.Int).Sub(mh1, mh2)
	tmp2 := new(big.Int).Sub(s1.S, s2.S)
	tmp2.Exp(tmp2, one, d.Q)
	tmp2.ModInverse(tmp2, d.Q)
	tmp.Mul(tmp, tmp2)
	tmp.Exp(tmp, one, d.Q)

	k := tmp
	privateKey := challenge43.RecoverPrivate(d, mhash1[:], s1, k)

	return privateKey
}
