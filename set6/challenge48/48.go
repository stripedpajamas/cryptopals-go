package challenge48

import (
	"github.com/stripedpajamas/cryptopals/set5/challenge39"
	"github.com/stripedpajamas/cryptopals/set6/challenge47"
)

var rsa = challenge39.RSA{}

func init() {
	rsa.Initialize(1024)
}

// Oracle returns true if the decrypted ciphertext has valid padding
// valid meaning pt[0] = 0, pt[1] = 2 (at least for now)
func Oracle(ciphertext []byte) bool {
	challenge47.OracleCalls++
	pt := rsa.Decrypt(ciphertext)
	// append a 0 to account for the translation from numbers into bytes
	pt = append([]byte{0}, pt...)

	return pt[0] == 0 && pt[1] == 2
}
