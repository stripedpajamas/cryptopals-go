package challenge57

import "testing"

import "math/big"

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
