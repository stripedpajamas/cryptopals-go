package challenge32

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stripedpajamas/cryptopals/set4/challenge31"
)

func init() {
	// start up the server first
	go challenge31.HmacServer(25)

	// sleep for a second to make sure the server is up
	time.Sleep(5 * time.Second)
}

func TestDiscoverValidMAC(t *testing.T) {
	want := challenge31.HmacSha1(challenge31.Secret, []byte("foo"))
	got := DiscoverValidMAC("foo", true)

	if !bytes.Equal(want[0:20], got) {
		fmt.Printf("Wanted: \t%x\nGot: \t\t%x\n", want, got)
		t.Fail()
	}
}
