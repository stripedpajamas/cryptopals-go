package challenge50

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"github.com/stripedpajamas/cryptopals/set7/challenge49"
)

func TestForgeScript(t *testing.T) {
	plaintext := challenge9.Pad([]byte("alert('MZA who was that?');\n"), 16)
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	key := []byte("YELLOW SUBMARINE")
	hash := challenge49.CBCMAC(plaintext, iv, key)

	expectedHash := []byte{0x29, 0x6b, 0x8d, 0x7c, 0xb7, 0x8a, 0x24, 0x3d, 0xda, 0x4d, 0xa, 0x61, 0xd3, 0x3b, 0xbd, 0xd1}

	if !bytes.Equal(hash, expectedHash) {
		t.Fail()
	}

	// now generate a collision
	myScript := ForgeScript(key)
	fmt.Printf("%v\n%s\n", myScript, string(myScript))
	myHash := challenge49.CBCMAC(myScript, iv, key)

	if !bytes.Equal(myHash, expectedHash) {
		t.Fail()
	}
}
