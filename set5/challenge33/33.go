package challenge33

import (
	"math/big"
)

type DH struct {
	p *big.Int
	g *big.Int
}

func (dh *DH) SetVars(p, g *big.Int) {
	dh.p, dh.g = p, g
}

func (dh *DH) GetPublic(a *big.Int) *big.Int {
	// make sure we are mod p
	priv := a.Mod(a, dh.p)

	// public is g^a mod p
	return dh.g.Exp(dh.g, priv, dh.p)
}

func (dh *DH) GetSession(otherPub, myPriv *big.Int) *big.Int {
	// session key is B^a (mod p) where B is Bob's public and a is Alice's private
	return otherPub.Exp(otherPub, myPriv, dh.p)
}
