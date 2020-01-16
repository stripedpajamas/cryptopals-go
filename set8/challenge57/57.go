package challenge57

import (
	"fmt"
	"math/big"
)

// DiscoverSecretKey attempts to recover the secret key of the other party
// in a Diffie-Hellman key exchange
func DiscoverSecretKey(p, g, q *big.Int, getBobMessage func(*big.Int) (string, []byte)) *big.Int {
	return new(big.Int)
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
	printFactors(factors)
	one := big.NewInt(1)
	for _, f := range factors {
		if gcd := new(big.Int).GCD(nil, nil, f, factor); gcd.Cmp(one) != 0 {
			// `factor` is not coprime to an already seen factor
			return false
		}
	}
	return true
}
