package challenge49

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
)

func TestCBCMAC(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	key := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	mac := CBCMAC(plaintext, iv, key)
	want := []byte{0x20, 0xd0, 0xd9, 0xcb, 0x2b, 0x0, 0x60, 0x8d, 0xe8, 0xe3, 0xd, 0x57, 0xf7, 0xc5, 0x81, 0x98}

	if !bytes.Equal(mac, want) {
		t.Fail()
	}
}

func TestServerClientV1(t *testing.T) {
	sharedKey := challenge11.GenerateRandomKey()
	server := &ServerV1{
		key: sharedKey,
	}
	normalClient := &ClientV1{
		account:  1,
		key:      sharedKey,
		sendFunc: Send,
	}

	response := normalClient.Transfer(2, 100, server)

	if !response.success {
		t.Fail()
	}

	// now try to fake a transfer
	myMessage := url.Values{
		"from":   []string{"1"},
		"to":     []string{"2"},
		"amount": []string{"999"},
	}
	message := []byte(myMessage.Encode())
	invalidRequest := &TransferRequestV1{
		message: message,
		iv:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 9, 8, 7, 6, 5, 4},
		mac:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 9, 8, 7, 6, 5, 4},
	}

	response = Send(server, invalidRequest)

	// should not be allowed because the mac is no bueno
	if response.success {
		t.Fail()
	}
}

func TestServerForgerV1(t *testing.T) {
	sharedKey := challenge11.GenerateRandomKey()
	server := &ServerV1{
		key: sharedKey,
	}
	forgerClient := &ClientV1{
		account:  9,
		key:      sharedKey,
		sendFunc: ForgeSend,
	}

	response := forgerClient.Transfer(1, 1000000, server)

	if !response.success || response.from != 1 || response.to != 9 {
		t.Fail()
	}
}
