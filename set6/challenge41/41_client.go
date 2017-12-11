package challenge41

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
)

type ReceivedPlaintext struct {
	PT string
}

var PubInfo Pub

func Client(pt []byte, sendFunc func([]byte, chan bool)) {
	// get pub info
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

	client := challenge39.RSA{}
	client.Initialize()

	// encrypt something
	ct := client.Encrypt(pt, serverN, serverE)

	// at this point send through the 'internet' so we can capture it and play with it
	signal := make(chan bool)
	go sendFunc(ct, signal)

	// post up to the server to see the PT
	post, err := json.Marshal(Ciphertext{CT: base64.StdEncoding.EncodeToString(ct)})
	if err != nil {
		panic(err)
	}

	resp, err = http.Post("http://127.0.0.1:8000/decrypt", "application/json", bytes.NewBuffer(post))
	if err != nil {
		panic(err)
	}

	var recPTb64 ReceivedPlaintext
	decoder = json.NewDecoder(resp.Body)
	err = decoder.Decode(&recPTb64)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	recPT, err := base64.StdEncoding.DecodeString(recPTb64.PT)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(recPT, pt) {
		panic("Server decryption not working")
	}

	<-signal
}
