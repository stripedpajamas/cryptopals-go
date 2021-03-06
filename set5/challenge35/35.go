package challenge35

import (
	"crypto/rand"
	"crypto/sha1"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set2/challenge10"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set5/challenge33"
)

type stash struct {
	key          []byte
	DiscoveredPT [][]byte
	ptIdx        int
	pMinusOne    []byte
}

var eveStash stash = stash{
	DiscoveredPT: make([][]byte, 2),
	ptIdx:        0,
}

func SendThroughEve(input [][]byte) [][]byte {
	// similar to 34's malicious listener, but we are just exploiting bad g values
	switch len(input) {
	case 3:
		// [p, g, A]
		// we won't mess with anything, but we'll note g and act on it
		p := new(big.Int)
		p.SetBytes(input[0])
		pMinusOne := new(big.Int)
		pMinusOne.SetBytes(input[0])
		pMinusOne.Sub(pMinusOne, big.NewInt(1))
		g := new(big.Int)
		g.SetBytes(input[1])
		A := new(big.Int)
		A.SetBytes(input[2])

		var sha [20]byte
		if g.Cmp(big.NewInt(1)) == 0 {
			// if g == 1
			sha = sha1.Sum([]byte{1})
		} else if g.Cmp(pMinusOne) == 0 {
			// if g == p - 1, then the session will either be 1 or p-1.
			// if either of the public keys is 1, the session key will be 1
			// if both of the their public keys are p-1, the session key will be p-1
			// so we will wait until we have Bob's public key to make the decision if Alice's is p-1
			if A.Cmp(big.NewInt(1)) == 0 {
				sha = sha1.Sum([]byte{1})
			} else {
				// Alice's is p-1, so put p-1 in a var for us to use later if Bob's pub is also p-1
				eveStash.pMinusOne = pMinusOne.Bytes()
			}
		} else if g.Cmp(p) == 0 {
			sha = sha1.Sum([]byte{})
		}
		eveStash.key = sha[0:16]
	case 2:
		// [iv, ct]
		// we don't change this but we can read it
		eveStash.DiscoveredPT[eveStash.ptIdx] = challenge10.CBCDecrypter(input[0], input[1], eveStash.key)
		eveStash.ptIdx++
	case 1:
		// [B]
		if eveStash.pMinusOne != nil {
			B := new(big.Int)
			B.SetBytes(input[0])
			// if it's not 1, it's p-1
			var sha [20]byte
			if B.Cmp(big.NewInt(1)) != 0 {
				// this means both Alice and Bob's pub is p-1, which means the resulting session key will
				// also be p-1
				sha = sha1.Sum(eveStash.pMinusOne)
				eveStash.key = sha[0:16]
			}
		}
	}
	return input
}

func ResetEveStash() {
	eveStash = stash{
		DiscoveredPT: make([][]byte, 2),
		ptIdx:        0,
	}
}

func SendNormal(input [][]byte) [][]byte {
	// this is a simple 'send through the internet' where no is manipulating
	return input
}

func AliceAndBob(gBytes []byte, sendFunc func([][]byte) [][]byte) [][]byte {
	// exactly same as 34 except g can be specified here
	alicePBytes := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0xf, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x2, 0x4e, 0x8, 0x8a, 0x67, 0xcc, 0x74, 0x2, 0xb, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x8, 0x79, 0x8e, 0x34, 0x4, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0xa, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0xb, 0xff, 0x5c, 0xb6, 0xf4, 0x6, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x0, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x5, 0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x7, 0x70, 0x96, 0x96, 0x6d, 0x67, 0xc, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x4, 0xf1, 0x74, 0x6c, 0x8, 0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	aliceP := new(big.Int)
	aliceP.SetBytes(alicePBytes)

	aliceG := new(big.Int)
	aliceG.SetBytes(gBytes)
	aliceGBytes := gBytes

	alice := challenge33.DH{}
	alice.SetVars(aliceP, aliceG)

	// generate a big random number for alice private
	alicePrivateBytes := make([]byte, 1024)
	_, err := rand.Read(alicePrivateBytes)
	if err != nil {
		panic(err)
	}
	alicePrivate := new(big.Int)
	alicePrivate.SetBytes(alicePrivateBytes)
	alicePublic := alice.GetPublic(alicePrivate)
	alicePublicBytes := alicePublic.Bytes()

	// now we send p, g, A to Bob in the form [ [pBytes], [gBytes], [aBytes] ]
	payload := [][]byte{
		alicePBytes,
		aliceGBytes,
		alicePublicBytes,
	}
	bobReceived := sendFunc(payload)

	// bob then sets up his environment with what was sent
	bob := challenge33.DH{}
	bobPBytes := bobReceived[0]
	bobGBytes := bobReceived[1]
	bobABytes := bobReceived[2]

	bobP := new(big.Int)
	bobP.SetBytes(bobPBytes)
	bobG := new(big.Int)
	bobG.SetBytes(bobGBytes)

	bob.SetVars(bobP, bobG)

	// makes his own private
	bobPrivateBytes := make([]byte, 1024)
	_, err = rand.Read(bobPrivateBytes)
	if err != nil {
		panic(err)
	}
	bobPrivate := new(big.Int)
	bobPrivate.SetBytes(bobPrivateBytes)
	// gets his own public
	bobPublic := bob.GetPublic(bobPrivate)
	bobPublicBytes := bobPublic.Bytes()

	// and sends his own public to Alice
	payload = [][]byte{
		bobPublicBytes,
	}
	aliceReceived := sendFunc(payload)

	// alice has bob's public now
	aliceBBytes := aliceReceived[0]
	aliceBobPublic := new(big.Int)
	aliceBobPublic.SetBytes(aliceBBytes)

	// now Alice generates a session key from the info she has
	aliceSessionSeed := alice.GetSession(aliceBobPublic, alicePrivate)
	aliceSessionSeedBytes := aliceSessionSeed.Bytes()

	// and generates a 16-byte key from it by taking the first 16 bytes of a SHA1 hash of the seed
	aliceSessionSHA := sha1.Sum(aliceSessionSeedBytes)
	aliceKey := aliceSessionSHA[0:16]

	// meanwhile, bob is able to generate his own session key with the same logic
	bobAlicePublic := new(big.Int)
	bobAlicePublic.SetBytes(bobABytes)
	bobSessionSeed := bob.GetSession(bobAlicePublic, bobPrivate)
	bobSessionSeedBytes := bobSessionSeed.Bytes()
	bobSessionSHA := sha1.Sum(bobSessionSeedBytes)
	bobKey := bobSessionSHA[0:16]

	// alice now sends a message to bob using the derived key
	aMessagePT := []byte("hello bob. i think you should by amazon stock -a")
	aRandomIV := challenge11.GenerateRandomKey()
	aMessageCT := challenge10.CBCEncrypter(aRandomIV, aMessagePT, aliceKey)

	payload = [][]byte{
		aRandomIV,
		aMessageCT,
	}
	bobReceived = sendFunc(payload)

	// bob decrypts the message with the key has derived
	bobDecrypted := challenge10.CBCDecrypter(bobReceived[0], bobReceived[1], bobKey)

	// bob now sends back what he thinks alice's original message was
	bRandomIV := challenge11.GenerateRandomKey()
	bMessageCT := challenge10.CBCEncrypter(bRandomIV, bobDecrypted, bobKey)

	payload = [][]byte{
		bRandomIV,
		bMessageCT,
	}
	aliceReceived = sendFunc(payload)

	// alice decrypts the message with her key
	aliceDecrypted := challenge10.CBCDecrypter(aliceReceived[0], aliceReceived[1], aliceKey)

	// return the decrypted stuff for testing
	return [][]byte{
		aliceDecrypted,
		bobDecrypted,
	}
}
