package challenge5

import (
	"testing"
)

func TestRepeatingKeyXORStrings(t *testing.T) {
	c5plaintext := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	c5key := "ICE"
	c5ExpectedOutput := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	c5output := RepeatingKeyXORStrings(c5plaintext, c5key)

	if c5output != c5ExpectedOutput {
		t.Fail()
	}
}
