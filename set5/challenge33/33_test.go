package challenge33

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestDiffieHellman(t *testing.T) {
	// tiny DH test
	alice := DH{P: big.NewInt(37), G: big.NewInt(5)}
	alicePrivate := big.NewInt(123)
	alicePublic := alice.GetPublic(alicePrivate)

	if alicePublic.Cmp(big.NewInt(29)) != 0 {
		t.Fail()
	}

	// here we simulate bob receiving a new transmission from alice
	// bob starts with no knowledge of p or g
	bob := DH{}
	// receives p & g from alice and sets them
	bob.SetVars(big.NewInt(37), big.NewInt(5))
	// makes his own private
	bobPrivate := big.NewInt(457)
	// gets his own public
	bobPublic := bob.GetPublic(bobPrivate)

	if bobPublic.Cmp(big.NewInt(19)) != 0 {
		t.Fail()
	}

	// now both should be able to make a session key (or at least the seed of a key)
	aliceSession := alice.GetSession(bobPublic, alicePrivate)
	bobSession := bob.GetSession(alicePublic, bobPrivate)

	if aliceSession.Cmp(bobSession) != 0 {
		t.Fail()
	}
}

func TestDiffieHellmanBig(t *testing.T) {
	// DH test with big nums (https://cryptopals.com/sets/5/challenges/33)
	pString := "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
	pBytes, err := hex.DecodeString(pString)
	if err != nil {
		t.Fail()
	}
	p := new(big.Int)
	p.SetBytes(pBytes)
	g := big.NewInt(2)
	alice := DH{P: p, G: g}

	// generate a big random number for alice
	alicePrivateBytes := make([]byte, 1024)
	_, err = rand.Read(alicePrivateBytes)
	if err != nil {
		t.Fail()
	}
	alicePrivate := new(big.Int)
	alicePrivate.SetBytes(alicePrivateBytes)
	alicePublic := alice.GetPublic(alicePrivate)

	// here we simulate bob receiving a new transmission from alice
	// bob starts with no knowledge of p or g
	bob := DH{}
	// receives p & g from alice and sets them
	bob.SetVars(p, g)
	// makes his own private
	bobPrivateBytes := make([]byte, 1024)
	_, err = rand.Read(bobPrivateBytes)
	if err != nil {
		t.Fail()
	}
	bobPrivate := new(big.Int)
	bobPrivate.SetBytes(bobPrivateBytes)
	// gets his own public
	bobPublic := bob.GetPublic(bobPrivate)

	// now both should be able to make a session key (or at least the seed of a key)
	aliceSession := alice.GetSession(bobPublic, alicePrivate)
	bobSession := bob.GetSession(alicePublic, bobPrivate)

	if aliceSession.Cmp(bobSession) != 0 {
		t.Fail()
	}
}
