package challenge31

import (
	"fmt"
	"testing"
)

func TestHmacSha1(t *testing.T) {
	// HMAC_SHA1("", "")
	// fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
	key := []byte("")
	message := []byte("")
	if fmt.Sprintf("%x", HmacSha1(key, message)) != "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d" {
		t.Fail()
	}

	// HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")
	// de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
	key = []byte("key")
	message = []byte("The quick brown fox jumps over the lazy dog")
	if fmt.Sprintf("%x", HmacSha1(key, message)) != "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9" {
		t.Fail()
	}
}
