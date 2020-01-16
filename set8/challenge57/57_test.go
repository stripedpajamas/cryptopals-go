package challenge57

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
	"testing"
)

func getChallengeParams() (*big.Int, *big.Int, *big.Int) {
	p, ok := new(big.Int).SetString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)
	if !ok {
		panic("could not create p")
	}
	g, ok := new(big.Int).SetString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)
	if !ok {
		panic("could not create g")
	}
	q, ok := new(big.Int).SetString("236234353446506858198510045061214171961", 10)
	if !ok {
		panic("could not create q")
	}

	return p, g, q
}

func TestGetFactors(t *testing.T) {
	p := big.NewInt(41761)
	q := big.NewInt(144)
	factors := GetFactors(p, q)

	// coprime factors of (41761 - 1) / 144 = 290 up until their product > 144
	expected := []*big.Int{big.NewInt(2), big.NewInt(5), big.NewInt(29)}

	if len(factors) != len(expected) {
		t.Fatalf("list of factors has different length than expected; wanted %d, got %d", len(expected), len(factors))
	}
	for idx := range factors {
		if expected[idx].Cmp(factors[idx]) != 0 {
			t.Errorf("factors not equal; wanted %s, got %s", expected[idx].String(), factors[idx].String())
		}
	}
}

func TestSolveChineseRemainder(t *testing.T) {
	// two examples from wikipedia
	residues := []*Residue{
		&Residue{remainder: big.NewInt(2), modulus: big.NewInt(3)},
		&Residue{remainder: big.NewInt(3), modulus: big.NewInt(5)},
		&Residue{remainder: big.NewInt(2), modulus: big.NewInt(7)},
	}
	expected := big.NewInt(23)
	if answer := SolveChineseRemainder(residues); answer.Cmp(expected) != 0 {
		t.Errorf("wrong answer for chinese remainder problem; wanted %s, got %s", expected.String(), answer.String())
	}
}

func TestDiscoverSecretKey(t *testing.T) {
	t.SkipNow()
	// modeling this attack as a malicious client (Eve) repeatedly
	// accessing a server (Bob)

	p, g, q := getChallengeParams()
	bob := NewDH(p, g)
	if _, err := bob.Init(); err != nil {
		t.Fatal("failed to initialize for bob")
	}

	// getBobMessage takes your public key, has bob compute his secret
	// and the shared secret, and then uses the shared secret to hmac a
	// message; the message and tag are returned to the client for validation
	var getBobMessage func(*big.Int) (string, []byte)

	getBobMessage = func(yourPublicKey *big.Int) (string, []byte) {
		shared := bob.ComputeSharedSecret(yourPublicKey)
		msg := "crazy flamboyant for the rap enjoyment"
		h := hmac.New(sha256.New, shared.Bytes())
		h.Write([]byte(msg))
		mac := h.Sum(nil)
		return msg, mac
	}

	bobSecretKey := DiscoverSecretKey(p, g, q, getBobMessage)

	if bob.secret.Cmp(bobSecretKey) != 0 {
		t.Errorf("failed to discover secret key; wanted %s, got %s", bob.secret.String(), bobSecretKey.String())
	}
}

func TestContrivedDH(t *testing.T) {
	p, g, _ := getChallengeParams()
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
