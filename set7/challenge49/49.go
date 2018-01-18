package challenge49

import (
	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

func CBCMAC(plaintext, iv, key []byte) []byte {
	enc := challenge10.CBCEncrypter(iv, challenge9.Pad(plaintext, 16), key)
	blocks := len(enc) / 16
	return enc[(blocks-1)*16:]
}

func Send(s *ServerV1, t *TransferRequestV1) TransferResponse {
	return s.Transfer(t)
}

func ForgeSend(s *ServerV1, t *TransferRequestV1) TransferResponse {
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
