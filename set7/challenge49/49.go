package challenge49

import (
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
)

func CBCMAC(plaintext, iv, key []byte) []byte {
	// assuming plaintext is already a good length (multiple of blocksize)
	enc := challenge10.CBCEncrypter(iv, plaintext, key)
	blocks := len(enc) / 16
	return enc[(blocks-1)*16:]
}

func SendV1(s *ServerV1, t *TransferRequestV1) TransferResponseV1 {
	return s.Transfer(t)
}

func SendV2(s *ServerV2, t *TransferRequestV2) TransferResponseV2 {
	return s.Transfer(t)
}

func ForgeSend(s *ServerV1, t *TransferRequestV1) TransferResponseV1 {
	// we are expecting a VALID transfer request (properly signed)
	// that has from: 9 (the attacker account id), to: 1 (the target), amount: 1000000
	// we will make 9 = 1 and 1 = 9 in the message, and then flip the corresponding bits
	// in the IV that is sent up, which should result in a successful transfer FROM the target
	// TO the attacker :)

	// from=9&to=1...
	t.message[5], t.message[10] = t.message[10], t.message[5]

	// the new IV bit = the old iv bit ^ the old corresponding msg bit ^ the desired msg bit
	t.iv[5] = t.iv[5] ^ t.message[5] ^ t.message[10]
	t.iv[10] = t.iv[10] ^ t.message[10] ^ t.message[5]

	return s.Transfer(t)
}

var capturedRequest *TransferRequestV2

func LengthExtensionSend(s *ServerV2, t *TransferRequestV2) TransferResponseV2 {
	// the idea here is to capture a valid message from the client of form
	// from=1&tx_list=2:50;3:45 etc etc
	// and also capture one of our own valid messages of the same form, but specifically
	// with the second block of the message having a transaction to ourselves with amount
	// 1000000
	// to do this in this weird test environment, we'll kind of "expect" a message from
	// ourselves and store it for later, and then the second message that comes through
	// we can tamper with
	if capturedRequest == nil {
		// this is the first message (our own) coming through
		capturedRequest = t
		// return a blank response (don't let the server process it, as it's bogus)
		return TransferResponseV2{}
	}
	// this is the message coming in from the client, and we already have our own
	// message captured. our magic transaction begins in block 2. we need to xor block 1
	// with the mac of this message
	bridgeBlock := make([]byte, 16)
	copy(bridgeBlock, capturedRequest.message[:16])
	for idx, b := range t.mac {
		bridgeBlock[idx] = bridgeBlock[idx] ^ b
	}
	t.message = append(t.message, bridgeBlock...)
	t.message = append(t.message, capturedRequest.message[16:]...)

	t.mac = capturedRequest.mac

	return s.Transfer(t)
}
