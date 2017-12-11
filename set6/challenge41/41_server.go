package challenge41

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
)

type Pub struct {
	N []byte
	E []byte
}

type Ciphertext struct {
	CT string // expecting a base64 string
}
type Plaintext struct {
	PT []byte
}

var RSA challenge39.RSA = challenge39.RSA{}
var previousMessages sync.Map = sync.Map{}

func HandlePubRoute(w http.ResponseWriter, r *http.Request) {
	// just sends back N,e for people to encrypt stuff
	pub, err := json.Marshal(Pub{
		N: RSA.N.Bytes(),
		E: RSA.E.Bytes(),
	})
	if err != nil {
		panic(err)
	}

	w.WriteHeader(200)
	w.Write(pub)
}

func HandleDecryptRoute(w http.ResponseWriter, r *http.Request) {
	// decode the json sent { "CT": "0xABCDEF" }
	decoder := json.NewDecoder(r.Body)
	var decoded Ciphertext
	err := decoder.Decode(&decoded)
	if err != nil {
		panic(err)
	}
	defer r.Body.Close()

	// decode the base64 into a byte array
	ct, err := base64.StdEncoding.DecodeString(decoded.CT)
	if err != nil {
		panic(err)
	}

	// take a hash of the ct to see if we're allowed to decrypt this
	hash := sha1.Sum(ct)
	found, _ := previousMessages.Load(hash)
	if found == true {
		w.WriteHeader(200)
		// tell client that the PT was already decrypted
		w.Write([]byte(`{"PT": "TWVzc2FnZSBhbHJlYWR5IGRlY3J5cHRlZA=="}`))
		return
	}

	// add it to our hash map
	previousMessages.Store(hash, true)

	// decrypt it
	pt := RSA.Decrypt(ct)

	// json it
	sendBack, err := json.Marshal(Plaintext{PT: pt})
	if err != nil {
		panic(err)
	}
	// send it back
	w.WriteHeader(200)
	w.Write(sendBack)
}

func Server() {
	// server has rsa stuff so
	RSA.Initialize()

	// will decrypt something once for you using its private key
	http.HandleFunc("/decrypt", HandleDecryptRoute)
	http.HandleFunc("/pub", HandlePubRoute)
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		panic(err)
	}
}
