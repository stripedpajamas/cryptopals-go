package challenge33

import (
	"math/big"
	//"fmt"
)

type DH struct {
	P *big.Int
	G *big.Int
}

func (dh *DH) SetVars(p, g *big.Int) {
	dh.P, dh.G = p, g
}

func (dh *DH) GetPublic(a *big.Int) *big.Int {
	// public is g^a mod p
	pub := new(big.Int)
	pub.Exp(dh.G, a, dh.P)
	return pub
}

func (dh *DH) GetSession(otherPub, myPriv *big.Int) *big.Int {
	//fmt.Printf("Getting session with: \n%#v\n%#v\n", otherPub.Bytes(), myPriv.Bytes())
	// session key is B^a (mod p) where B is Bob's public and a is Alice's private
	ses := new(big.Int)
	ses.Exp(otherPub, myPriv, dh.P)
	return ses
}
