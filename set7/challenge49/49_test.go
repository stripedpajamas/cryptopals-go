package challenge49

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/stripedpajamas/cryptopals/set2/challenge9"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
)

func TestCBCMAC(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	paddedPT := challenge9.Pad(plaintext, 16)
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	key := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	mac := CBCMAC(paddedPT, iv, key)
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
		sendFunc: SendV1,
	}

	response := normalClient.Transfer(2, 100, server)

	if !response.success {
		t.Fail()
	}

	// now try to fake a transfer
	myMessage := url.Values{}
	myMessage.Add("from", "1")
	myMessage.Add("to", "2")
	myMessage.Add("amount", "999")

	message := []byte(myMessage.Encode())
	paddedMessage := challenge9.Pad(message, 16)
	invalidRequest := &TransferRequestV1{
		message: paddedMessage,
		iv:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 9, 8, 7, 6, 5, 4},
		mac:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 9, 8, 7, 6, 5, 4},
	}
	response = SendV1(server, invalidRequest)

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

func TestServerClientV2(t *testing.T) {
	sharedKey := challenge11.GenerateRandomKey()
	sharedIV := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	server := &ServerV2{
		key: sharedKey,
		iv:  sharedIV,
	}
	normalClient := &ClientV2{
		account:  1,
		key:      sharedKey,
		iv:       sharedIV,
		sendFunc: SendV2,
	}

	txList := []Transaction{
		{to: 2, amount: 50},
		{to: 3, amount: 45},
	}

	response := normalClient.Transfer(txList, server)

	if !response.success {
		t.Fail()
	}

	// now try to fake a transfer
	myMessage := url.Values{}
	myMessage.Add("from", "1")
	myMessage.Add("tx_list", "2:500;3:140")

	message := []byte(myMessage.Encode())
	invalidRequest := &TransferRequestV2{
		message: message,
		mac:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 9, 8, 7, 6, 5, 4},
	}

	response = SendV2(server, invalidRequest)

	// should not be allowed because the mac is no bueno
	if response.success {
		t.Fail()
	}
}

func TestLengthExtension(t *testing.T) {
	sharedKey := challenge11.GenerateRandomKey()
	sharedIV := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	server := &ServerV2{
		key: sharedKey,
		iv:  sharedIV,
	}
	normalClient := &ClientV2{
		account:  1,
		key:      sharedKey,
		iv:       sharedIV,
		sendFunc: LengthExtensionSend,
	}
	txList := []Transaction{
		{to: 2, amount: 50},
		{to: 3, amount: 45},
	}

	attackerClient := &ClientV2{
		account:  9,
		key:      sharedKey,
		iv:       sharedIV,
		sendFunc: LengthExtensionSend,
	}

	// multiple transactions to ensure we have the ';' and also that we don't
	// have to deal with padding
	attackerTxList := []Transaction{
		{to: 9, amount: 1},
		{to: 9, amount: 1000000},
	}

	// attacker sends first to cache the request for later use
	attackerClient.Transfer(attackerTxList, server)
	response := normalClient.Transfer(txList, server)

	finalTransaction := response.txList[len(response.txList)-1]
	if finalTransaction.to != 9 || finalTransaction.amount != 1000000 {
		t.Fail()
	}
}
