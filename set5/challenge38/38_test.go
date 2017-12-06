package challenge38

import (
	"bytes"
	"testing"
)

func TestLogin(t *testing.T) {
	if !Login([]byte("tomato"), SendNormal) {
		t.Fail()
	}
}

func TestDictionaryAttack(t *testing.T) {
	// apple appears on the 11838th line of our wordlist
	Login([]byte("abashed"), SendThroughEve)
	if !bytes.Equal(EveRemembers.Password, []byte("abashed")) {
		t.Fail()
	}
}
