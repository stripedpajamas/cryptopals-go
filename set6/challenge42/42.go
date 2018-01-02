package challenge42

import (
	"crypto"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
	"github.com/stripedpajamas/cryptopals/set5/challenge40"
)

func ForgeSignature(inputHash []byte, N *big.Int) []byte {
	// so first we will hash the input and prepend it with the goop
	payload := append(challenge39.HashPrefixes[crypto.SHA256], inputHash[:]...)

	// then we will add the stuff that makes it look real
	totalLength := len(N.Bytes())
	sigBlock := make([]byte, totalLength)
	sigBlock[1] = 1
	sigBlock[2] = 0xFF
	sigBlock[3] = 0xFF

	copy(sigBlock[5:], payload)

	sig := new(big.Int).SetBytes(sigBlock)
	sigCubeRoot := challenge40.CubeRoot(sig)
	sigCubeRoot.Add(sigCubeRoot, big.NewInt(1))

	// my cube root is always 1 too small because of a rounding error or something
	// so here i am incrementing it
	return sigCubeRoot.Bytes()
}
