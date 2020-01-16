package challenge57

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestContrivedDH(t *testing.T) {
	p, ok := new(big.Int).SetString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)
	if !ok {
		t.Fatal("could not create p")
	}
	g, ok := new(big.Int).SetString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)
	if !ok {
		t.Fatal("could not create g")
	}
	alice := NewDH(p, g)
	bob := NewDH(p, g)

	aPub, err := alice.Init()
	if err != nil {
		t.Fatal("failed to initialize for alice")
	}
	bPub, err := bob.Init()
	if err != nil {
		t.Fatal("failed to initialize for bob")
	}

	// Alice -> Bob: aPub
	// Bob -> Alice: bPub

	aSharedSecret := alice.ComputeSharedSecret(bPub)
	bSharedSecret := bob.ComputeSharedSecret(aPub)

	if aSharedSecret.Cmp(bSharedSecret) != 0 {
		t.Errorf("shared secrets are not equal; alice: %s != bob: %s", aSharedSecret.String(), bSharedSecret.String())
	}

	// demonstrate bob sending alice an authenticated message
	// using the shared key, and alice finding it valid
	bobHasher := hmac.New(sha256.New, bSharedSecret.Bytes())
	msg := "crazy flamboyant for the rap enjoyment"
	bobHasher.Write([]byte(msg))
	mac := bobHasher.Sum(nil)

	// Bob -> Alice: msg, mac

	aliceHasher := hmac.New(sha256.New, aSharedSecret.Bytes())
	aliceHasher.Write([]byte(msg))
	expectedMac := aliceHasher.Sum(nil)
	if !hmac.Equal(mac, expectedMac) {
		t.Errorf("alice received invalid mac; wanted %0x, got %0x", expectedMac, mac)
	}
}

func TestDiffieHellman(t *testing.T) {
	p := big.NewInt(23)
	g := big.NewInt(5)
	alice := NewDH(p, g)
	bob := NewDH(p, g)

	aPub, err := alice.Init()
	if err != nil {
		t.Fatal("failed to initialize for alice")
	}
	bPub, err := bob.Init()
	if err != nil {
		t.Fatal("failed to initialize for bob")
	}

	aSharedSecret := alice.ComputeSharedSecret(bPub)
	bSharedSecret := bob.ComputeSharedSecret(aPub)

	if aSharedSecret.Cmp(bSharedSecret) != 0 {
		t.Errorf("shared secrets are not equal; alice: %s != bob: %s", aSharedSecret.String(), bSharedSecret.String())
	}
}
