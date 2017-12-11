package challenge41

import (
	"bytes"
	"testing"
	"time"
)

func init() {
	// start up server
	go Server()

	time.Sleep(5 * time.Second)
}

func TestEve(t *testing.T) {
	pt := []byte("help me i am a potato")
	Client(pt, Eve)

	if !bytes.Equal(pt, EveRemembers) {
		t.Fail()
	}
}
