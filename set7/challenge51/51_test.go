package challenge51

import (
	"testing"
)

func TestCompressionOracle(t *testing.T) {
	length := CompressionOracle([]byte("hello world"), true)

	if length != 133 {
		t.Fail()
	}
}

func TestGuessSessionKeyStream(t *testing.T) {
	guessedSessionKey := GuessSessionKeyStream(false)
	if string(guessedSessionKey) != "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n" {
		t.Fail()
	}
}

func TestGuessSessionKeyBlock(t *testing.T) {
	guessedSessionKey := GuessSessionKeyBlock(false)
	if string(guessedSessionKey) != "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n" {
		t.Fail()
	}
}
