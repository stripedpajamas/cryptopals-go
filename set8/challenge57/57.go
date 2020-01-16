package challenge57

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
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
		rem, err := bruteForceMac(msg, mac, r)
		if err != nil {
			panic("could not discover secret key")
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
	return new(big.Int)
}

func bruteForceMac(msg string, mac []byte, max *big.Int) (*big.Int, error) {
	bmsg := []byte(msg)

	var myMac []byte
	one := big.NewInt(1)
	candidate := big.NewInt(0)
	for !bytes.Equal(myMac, mac) && candidate.Cmp(max) < 0 {
		candidate.Add(candidate, one)
		h := hmac.New(sha256.New, candidate.Bytes())
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

	current := big.NewInt(2)
	for !haveEnoughFactors(factors, q) {
		if _, rem := new(big.Int).QuoRem(j, current, new(big.Int)); rem.Sign() == 0 {
			// we have a factor, but we want to make sure it's not a repeated factor
			if isNotRepeatedFactor(current, factors) {
				factors = append(factors, current)
			}
		}
		current = new(big.Int).Add(current, one)
	}

	return factors
}

func printFactors(factors []*big.Int) {
	for _, f := range factors {
		fmt.Println(f.String())
	}
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
