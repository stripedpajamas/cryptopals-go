package challenge47

import "github.com/stripedpajamas/cryptopals/set5/challenge39"

var rsa = challenge39.RSA{}

func init() {
	rsa.Initialize(256)
}

// PKCSOracle returns true if the decrypted ciphertext has valid padding
// valid meaning pt[0] = 0, pt[1] = 2 (at least for now)
func PKCSOracle(ciphertext []byte) bool {
	pt := rsa.Decrypt(ciphertext)
	return pt[0] == 0 && pt[1] == 2
}

