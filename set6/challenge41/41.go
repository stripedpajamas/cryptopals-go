package challenge41

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

var EveRemembers []byte

func Eve(input []byte, signal chan bool) {
	// input is a ciphertext that we want to decrypt with the server
	// but if we send it to the server, it will just say it's already happened
	// so we instead send a poop payload to the server and do some math

	// step one is we need to get the public info ourselves
	resp, err := http.Get("http://127.0.0.1:8000/pub")
	if err != nil {
		panic(err)
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&PubInfo)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	serverN := new(big.Int).SetBytes(PubInfo.N)
	serverE := new(big.Int).SetBytes(PubInfo.E)

	// now we set S to a number > 1 mod N
	// how about 2
	// C' = ((S**E mod N) C) mod N

	C := new(big.Int).SetBytes(input)

	S := big.NewInt(2)
	cPrime := new(big.Int).Exp(S, serverE, serverN)
	cPrime.Mul(cPrime, C)
	cPrimeBytes := cPrime.Bytes()

	// now we ask the server to decrypt it
	post, err := json.Marshal(Ciphertext{CT: base64.StdEncoding.EncodeToString(cPrimeBytes)})
	if err != nil {
		panic(err)
	}

	resp, err = http.Post("http://127.0.0.1:8000/decrypt", "application/json", bytes.NewBuffer(post))
	if err != nil {
		panic(err)
	}

	var pPrimeB64 ReceivedPlaintext
	decoder = json.NewDecoder(resp.Body)
	err = decoder.Decode(&pPrimeB64)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	// convert received PT to bytes
	pPrimeBytes, err := base64.StdEncoding.DecodeString(pPrimeB64.PT)
	if err != nil {
		panic(err)
	}

	// convert bytes to int
	pPrime := new(big.Int).SetBytes(pPrimeBytes)

	// original plaintext = pPrime / S (mod N) = pPrime * invmod(S, N) mod N
	tmp := new(big.Int).ModInverse(S, serverN)
	tmp.Mul(pPrime, tmp)
	tmp.Exp(tmp, big.NewInt(1), serverN)

	EveRemembers = tmp.Bytes()

	signal <- true
}
