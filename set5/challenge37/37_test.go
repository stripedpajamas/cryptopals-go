package challenge37

import (
	"testing"
	//"math/big"
)

func TestLogin(t *testing.T) {
	if !Login() {
		t.Fail()
	}
}

func TestLoginZero(t *testing.T) {
	// sending a zero as A and not sending the password
	if !LoginZero() {
		t.Fail()
	}
}

func TestLoginN(t *testing.T) {
	// sending N as A and not sending the password
	if !LoginN() {
		t.Fail()
	}
}
