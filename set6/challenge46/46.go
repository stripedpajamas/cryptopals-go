package challenge46

import (
	"fmt"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
)

var rsa = challenge39.RSA{}

func init() {
	rsa.Initialize(2048)
}

func Oracle(ciphertext []byte) bool {
	// true for even, false for odd
	decrypted := rsa.Decrypt(ciphertext)
	return decrypted[len(decrypted)-1]&1 == 0
}

func FindPlaintext(ciphertext []byte, N, E *big.Int) []byte {
	ct := new(big.Int).SetBytes(ciphertext)
	two := big.NewInt(2)
	two.Exp(two, E, N)
	twof := big.NewFloat(2)
	eps := big.NewFloat(0.1)
	upperBound := new(big.Float).SetInt(N).SetPrec(4096)
	lowerBound := big.NewFloat(0).SetPrec(4096)

	diff := new(big.Float).Sub(upperBound, lowerBound)
	// loop as long as difference is greater than 0.001
	for diff.Cmp(eps) > 0 {
		tmp := new(big.Float).Add(upperBound, lowerBound)
		// multiply ciphertext by 2
		ct.Mul(ct, two)
		if Oracle(ct.Bytes()) {
			// even
			upperBound.Quo(tmp, twof)
		} else {
			// odd
			lowerBound.Quo(tmp, twof)
		}
		diff.Sub(upperBound, lowerBound)
		fmt.Printf("%.f\n", upperBound)
	}

	pt, _ := upperBound.Int(nil)
	return pt.Bytes()
}
