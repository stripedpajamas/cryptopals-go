package challenge37

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func Login() bool {
	server, client := Start([]byte("test@test.com"), []byte("tomato"))

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

	// server sends salt and public key
	serverPayload := GetServerSaltPayload(&server, b)

	// server receives what client sent and generates a session key
	// recEmail := clientPayload[0]
	recA := new(big.Int)
	recA.SetBytes(clientPayload[1])
	server.GetSession(recA, b)

	// client receives what server sent and generates a session key
	recSalt := new(big.Int)
	recSalt.SetBytes(serverPayload[0])
	client.SetSalt(recSalt)

	recB := new(big.Int)
	recB.SetBytes(serverPayload[1])
	client.GetSession(recB, a, []byte("tomato"))

	// to confirm authentication, client sends HMAC(key, salt) to server
	// server also computes HMAC(key, salt) and if they match, return success
	clientAuthPayload := GetClientAuthPayload(&client)

	verified := ServerCheckAuth(&server, clientAuthPayload[0])

	return verified
}

func LoginZero() bool {
	server, client := Start([]byte("test@test.com"), []byte("tomato"))

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
	// instead of sending the normal payload, send a 0 as A
	clientPayload = [][]byte{
		[]byte("test@test.com"),
		big.NewInt(0).Bytes(),
	}

	// server sends salt and public key
	serverPayload := GetServerSaltPayload(&server, b)

	// server receives what client sent and generates a session key
	// recEmail := clientPayload[0]
	recA := new(big.Int)
	recA.SetBytes(clientPayload[1])
	server.GetSession(recA, b)

	// now the server should have generated a session key of 0, so we don't
	// need to do the math
	recSalt := new(big.Int)
	recSalt.SetBytes(serverPayload[0])
	client.SetSalt(recSalt)
	client.S = big.NewInt(0)
	client.K = sha256.Sum256(client.S.Bytes())

	// to confirm authentication, client sends HMAC(key, salt) to server
	// server also computes HMAC(key, salt) and if they match, return success
	clientAuthPayload := GetClientAuthPayload(&client)

	verified := ServerCheckAuth(&server, clientAuthPayload[0])

	return verified
}

func LoginN() bool {
	server, client := Start([]byte("test@test.com"), []byte("tomato"))

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
	// instead of sending the normal payload, send a N as A
	clientPayload = [][]byte{
		[]byte("test@test.com"),
		client.N.Bytes(),
	}

	// server sends salt and public key
	serverPayload := GetServerSaltPayload(&server, b)

	// server receives what client sent and generates a session key
	// recEmail := clientPayload[0]
	recA := new(big.Int)
	recA.SetBytes(clientPayload[1])
	server.GetSession(recA, b)

	fmt.Println(server.S)

	// now the server should have generated a session key of 0, so we don't
	// need to do the math
	recSalt := new(big.Int)
	recSalt.SetBytes(serverPayload[0])
	client.SetSalt(recSalt)
	client.S = big.NewInt(0)
	client.K = sha256.Sum256(client.S.Bytes())

	// to confirm authentication, client sends HMAC(key, salt) to server
	// server also computes HMAC(key, salt) and if they match, return success
	clientAuthPayload := GetClientAuthPayload(&client)

	verified := ServerCheckAuth(&server, clientAuthPayload[0])

	return verified
}
