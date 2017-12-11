package challenge39

import (
	"crypto/rand"
	"math/big"
)

type RSA struct {
	N *big.Int
	E *big.Int
	d *big.Int
}

func GetPrimes() (p, q, a, b *big.Int) {
	// returns two big primes and their respective minus ones
	// a = p-1
	// b = q-1
	p, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	q, err = rand.Prime(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	a = new(big.Int)
	b = new(big.Int)
	a.Sub(p, big.NewInt(1))
	b.Sub(q, big.NewInt(1))

	return p, q, a, b
}

func (r *RSA) Initialize() {
	p, q, a, b := GetPrimes()
	r.E = big.NewInt(3)          // e = 3
	et := new(big.Int).Mul(a, b) // et = (p-1)(q-1)

	// e must be coprime with (p-1)(q-1)
	for new(big.Int).GCD(nil, nil, r.E, et).Cmp(big.NewInt(1)) != 0 {
		p, q, a, b = GetPrimes()
		et = new(big.Int).Mul(a, b)
	}

	r.N = new(big.Int).Mul(p, q)           // N = pq
	r.d = new(big.Int).ModInverse(r.E, et) // de == 1 (mod totient(n))
}

func (r *RSA) Encrypt(input []byte, N, E *big.Int) []byte {
	m := new(big.Int).SetBytes(input)
	// encrypt: c = m**e%n
	return new(big.Int).Exp(m, r.E, r.N).Bytes()
}

func (r *RSA) Decrypt(input []byte) []byte {
	c := new(big.Int).SetBytes(input)
	// decrypt: m = c**d%n
	return new(big.Int).Exp(c, r.d, r.N).Bytes()
}
