package challenge38

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"
)

type Eve struct {
	A        *big.Int
	server   SRPServer
	b        *big.Int
	u        *big.Int
	Password []byte
}

var EveRemembers Eve = Eve{}
var dictionary [][]byte

func init() {
	// get dictionary
	dicBytes, err := ioutil.ReadFile("/usr/share/dict/words")
	if err != nil {
		panic(err)
	}
	dictionary = bytes.Split(dicBytes, []byte("\n"))
}

func DictionaryAttack(target []byte, A, u, b, N, salt *big.Int) []byte {
	// g = 2
	// x = sha256(salt|password)
	// v = g**x % n
	// S = (Av^u)^b % n
	// K = SHA256(S)
	// auth = hmac-sha256(k, salt)

	g := big.NewInt(2)

	var winner []byte
	guesses := 0
	startTime := time.Now()
	var processTime float64

	for _, guess := range dictionary {
		// keeping track of how many guesses
		guesses++

		xH := sha256.Sum256(append(salt.Bytes(), guess...))
		x := new(big.Int)
		x.SetBytes(xH[:])

		v := new(big.Int)
		v.Exp(g, x, N)

		S := new(big.Int)
		tmp := new(big.Int)
		tmp.Exp(v, u, N)
		tmp.Mul(A, tmp)
		S.Exp(tmp, b, N)

		K := sha256.Sum256(S.Bytes())

		hash := hmac.New(sha256.New, K[:])

		if bytes.Equal(target, hash.Sum(salt.Bytes())) {
			winner = guess
			break
		}
	}

	endTime := time.Since(startTime).Seconds()
	processTime = float64(guesses) / endTime
	fmt.Printf(
		"Took %f seconds\nPassword found after %d guesses\nGuessed ~%f passwords/s\n",
		endTime,
		guesses,
		processTime)
	return winner
}

func SendThroughEve(payload [][]byte) [][]byte {
	// malicious interceptor
	// we will pretend to be the server to the client

	switch len(payload) {
	case 2:
		// the first payload, client -> server, [email, A]
		// we don't need to tamper here, but we will store A for later
		tmp := new(big.Int)
		tmp.SetBytes(payload[1])
		EveRemembers.A = tmp
	case 3:
		// the server sends back the salt, public and u [salt, B, u]
		// we are pretending to be the server to the client, so we will
		// send back our own stuff
		EveRemembers.server = SRPServer{}
		N := new(big.Int)
		NBytes := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0xf, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x2, 0x4e, 0x8, 0x8a, 0x67, 0xcc, 0x74, 0x2, 0xb, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x8, 0x79, 0x8e, 0x34, 0x4, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0xa, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0xb, 0xff, 0x5c, 0xb6, 0xf4, 0x6, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x0, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x5, 0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x7, 0x70, 0x96, 0x96, 0x6d, 0x67, 0xc, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x4, 0xf1, 0x74, 0x6c, 0x8, 0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		N.SetBytes(NBytes)

		g := big.NewInt(2)
		k := big.NewInt(3)
		EveRemembers.server.Initialize(N, g, k, []byte{}, []byte{})

		// eve server generates private key
		bBytes := make([]byte, 128)
		_, err := rand.Read(bBytes)
		if err != nil {
			panic(err)
		}
		b := new(big.Int)
		b.SetBytes(bBytes)

		// eve server generates random u
		uBytes := make([]byte, 128)
		_, err = rand.Read(uBytes)
		if err != nil {
			panic(err)
		}
		u := new(big.Int)
		u.SetBytes(uBytes)

		EveRemembers.b = b
		EveRemembers.u = u

		return GetServerSaltPayload(&EveRemembers.server, b, u)
	case 1:
		// client -> server, sending just [hmac(k, salt)]
		// we now have a 'target' of what we want our own hmac to generate
		// so we will pass that to a dictionary attack
		// the client/server session will fail to verify because we were in the middle
		// but if the dictionary attack is successful, we should be able to login ourselves
		// without tampering anything
		EveRemembers.Password =
			DictionaryAttack(
				payload[0],
				EveRemembers.A,
				EveRemembers.u,
				EveRemembers.b,
				EveRemembers.server.N,
				EveRemembers.server.Salt,
			)
	}
	return payload
}

func SendNormal(payload [][]byte) [][]byte {
	return payload
}

func Login(password []byte, sendFunc func([][]byte) [][]byte) bool {
	server, client := Start([]byte("test@test.com"), password)

	// client generates private key
	aBytes := make([]byte, 128)
	_, err := rand.Read(aBytes)
	if err != nil {
		panic(err)
	}
	a := new(big.Int)
	a.SetBytes(aBytes)

	// server generates private key
	bBytes := make([]byte, 128)
	_, err = rand.Read(bBytes)
	if err != nil {
		panic(err)
	}
	b := new(big.Int)
	b.SetBytes(bBytes)

	var clientPayload [][]byte
	// client sends up email and public key
	clientPayload = GetClientEmailPayload(&client, a, []byte("test@test.com"))
	receivedByServer := sendFunc(clientPayload)

	// server generates random u
	uBytes := make([]byte, 128)
	_, err = rand.Read(uBytes)
	if err != nil {
		panic(err)
	}
	u := new(big.Int)
	u.SetBytes(uBytes)

	// server sends salt, public key, and u
	serverPayload := GetServerSaltPayload(&server, b, u)
	receivedByClient := sendFunc(serverPayload)

	// server receives what client sent and generates a session key
	// recEmail := clientPayload[0]
	recA := new(big.Int)
	recA.SetBytes(receivedByServer[1])
	server.GetSession(recA, b, u)

	// client receives what server sent and generates a session key
	recSalt := new(big.Int)
	recSalt.SetBytes(receivedByClient[0])
	client.SetSalt(recSalt)

	recB := new(big.Int)
	recB.SetBytes(receivedByClient[1])
	recU := new(big.Int)
	recU.SetBytes(receivedByClient[2])
	client.GetSession(recB, a, recU, password)

	// to confirm authentication, client sends HMAC(key, salt) to server
	// server also computes HMAC(key, salt) and if they match, return success
	clientAuthPayload := GetClientAuthPayload(&client)
	receivedByServer = sendFunc(clientAuthPayload)

	verified := ServerCheckAuth(&server, receivedByServer[0])

	return verified
}
