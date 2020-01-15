package challenge57

import "math/big"

import "crypto/rand"

// DH is a struct holding state for a Diffie Hellman key exchange
type DH struct {
	p *big.Int
	g *big.Int

	secret *big.Int
	public *big.Int
}

// NewDH returns a new Diffie Hellman instance
func NewDH(p, g *big.Int) *DH {
	return &DH{p: p, g: g}
}

// Init generates and stores a secret value and produces a public value
func (dh *DH) Init() (*big.Int, error) {
	secret, err := rand.Int(rand.Reader, dh.p)
	if err != nil {
		return nil, err
	}
	if secret.Sign() < 1 {
		secret.Add(secret, big.NewInt(1))
	}
	dh.secret = secret
	dh.public = new(big.Int).Exp(dh.g, dh.secret, dh.p)

	return dh.public, nil
}

// ComputeSharedSecret uses the other party's public value with
// the secret value from Init to compute a shared secret
func (dh *DH) ComputeSharedSecret(otherPub *big.Int) *big.Int {
	return new(big.Int).Exp(otherPub, dh.secret, dh.p)
}
