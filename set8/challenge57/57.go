package challenge57

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
	"math/rand"
	"time"
)

// Residue represents the congruency (x == `remainder` mod `modulus`)
// for computation using the Chinese Remainder Theorem
type Residue struct {
	remainder *big.Int
	modulus   *big.Int
}

// DiscoverSecretKey attempts to recover the secret key of the other party
// in a Diffie-Hellman key exchange
func DiscoverSecretKey(p, g, q *big.Int, getBobMessage func(*big.Int) (string, []byte)) *big.Int {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	factors := GetFactors(p, q)

	residues := []*Residue{}

	for _, r := range factors {
		pm1r := new(big.Int).Quo(pMinus1, r)
		h := big.NewInt(1)
		for h.Cmp(one) == 0 {
			h.Rand(rng, p).Exp(h, pm1r, p)
		}

		// pretend to bob that `h` is my public key, but `h` is not even a valid public key
		msg, mac := getBobMessage(h)
		rem, err := bruteForceMac(msg, mac, h, p, r)
		if err != nil {
			panic("could not brute force secret key")
		}
		residues = append(residues, &Residue{
			remainder: rem, modulus: r,
		})
	}

	return SolveChineseRemainder(residues)
}

// SolveChineseRemainder takes residues (remainders and moduli) and computes
// the smallest solution
func SolveChineseRemainder(residues []*Residue) *big.Int {
	if len(residues) < 2 {
		panic("not enough residues to compute solution")
	}
	acc := residues[0]
	for i := 1; i < len(residues); i++ {
		a1, a2 := acc.remainder, residues[i].remainder
		n1, n2 := acc.modulus, residues[i].modulus
		m1, m2 := new(big.Int), new(big.Int)

		solution := new(big.Int).GCD(m1, m2, n1, n2)

		left := new(big.Int).Mul(a1, m2)
		left.Mul(left, n2)

		right := new(big.Int).Mul(a2, m1)
		right.Mul(right, n1)

		solution.Add(left, right)
		combined := new(big.Int).Mul(n1, n2)

		solution.Mod(solution, combined)
		acc = &Residue{remainder: solution, modulus: combined}
	}
	return acc.remainder
}

func bruteForceMac(msg string, mac []byte, myPubKey, p, max *big.Int) (*big.Int, error) {
	bmsg := []byte(msg)

	var myMac []byte
	one := big.NewInt(1)
	candidate := big.NewInt(0)
	for !bytes.Equal(myMac, mac) && candidate.Cmp(max) < 0 {
		candidate.Add(candidate, one)
		key := new(big.Int).Exp(myPubKey, candidate, p)
		h := hmac.New(sha256.New, key.Bytes())
		h.Write(bmsg)
		myMac = h.Sum(nil)
	}

	if !bytes.Equal(myMac, mac) {
		return nil, errors.New("could not brute force mac")
	}

	return candidate, nil
}

// GetFactors takes as input `q`, where `g^q = 1 mod p`, and
// finds factors [r1, r2, ..., rn] of `j = (p-1) / q` until the
// factors' product exceeds `q`
func GetFactors(p, q *big.Int) []*big.Int {
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	j := new(big.Int).Quo(pMinus1, q)

	factors := make([]*big.Int, 0)

	// rule out evens
	two := big.NewInt(2)
	if _, rem := new(big.Int).QuoRem(j, two, new(big.Int)); rem.Sign() == 0 {
		factors = append(factors, two)
	}

	// crush everything else
	current := big.NewInt(3)
	for !haveEnoughFactors(factors, q) {
		if _, rem := new(big.Int).QuoRem(j, current, new(big.Int)); rem.Sign() == 0 {
			// we have a factor, but we want to make sure it's not a repeated factor
			if isNotRepeatedFactor(current, factors) {
				factors = append(factors, current)
			}
		}
		current = new(big.Int).Add(current, two)
	}

	return factors
}

// multiply all the factors together and see if they're > target size
func haveEnoughFactors(factors []*big.Int, target *big.Int) bool {
	product := big.NewInt(1)
	for _, factor := range factors {
		product.Mul(product, factor)
		if product.Cmp(target) > 0 {
			return true
		}
	}
	return false
}

func isNotRepeatedFactor(factor *big.Int, factors []*big.Int) bool {
	one := big.NewInt(1)
	for _, f := range factors {
		if gcd := new(big.Int).GCD(nil, nil, f, factor); gcd.Cmp(one) != 0 {
			// `factor` is not coprime to an already seen factor
			return false
		}
	}
	return true
}
