package challenge31

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"github.com/stripedpajamas/cryptopals/set1/challenge3"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"net/http"
	"net/url"
	"time"
)

var artificialDelay time.Duration
var Secret []byte = challenge11.GenerateRandomKey()

func HmacSha1(key, message []byte) [20]byte {
	keyLen := len(key)
	if keyLen > 64 {
		// keys longer than blocksize are shortened
		tmp := sha1.Sum(key)
		key = tmp[0:20]
	}
	if keyLen < 64 {
		// keys shorter than blocksize are zero-padded
		key = append(key, bytes.Repeat([]byte{0}, 64-keyLen)...)
	}

	oKeyPad := challenge3.XorBytes(bytes.Repeat([]byte{0x5c}, 64), key)
	iKeyPad := challenge3.XorBytes(bytes.Repeat([]byte{0x36}, 64), key)

	tmp := sha1.Sum(append(iKeyPad, message...))
	return sha1.Sum(append(oKeyPad, tmp[0:20]...))
}

func InsecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
		// artificial time delay
		time.Sleep(time.Millisecond * artificialDelay)
	}
	return true
}

func handleFunc(w http.ResponseWriter, r *http.Request) {
	qs, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		panic(err)
	}

	fileName := qs.Get("file")
	signatureString := qs.Get("signature")
	// check for 'file' and 'signature' in query string
	if fileName == "" || signatureString == "" {
		w.WriteHeader(500)
		w.Write([]byte("Missing file or signature"))
		return
	}

	// decode signature
	//fmt.Println(signatureString)
	signature, err := hex.DecodeString(signatureString)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Invalid signature supplied"))
		return
	}

	// generate proper signature
	validSignature := HmacSha1(Secret, []byte(fileName))

	if !InsecureCompare(signature, validSignature[0:20]) {
		w.WriteHeader(500)
		w.Write([]byte("Invalid signature supplied"))
		return
	}
	w.WriteHeader(200)
	w.Write([]byte("Success!"))
}

func HmacServer(wait time.Duration) {
	artificialDelay = wait
	http.HandleFunc("/test", handleFunc)
	http.ListenAndServe(":8000", nil)
}
