package challenge19

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set3/challenge18"
)

var ptBase64Array []string = []string{
	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
}

type CTJsonStruct struct {
	CT [][]byte
}
type PTJsonStruct struct {
	PT []string `json:"PT"`
}

var ctJsonStruct CTJsonStruct
var ptJsonStruct PTJsonStruct
var ptArray [][]byte
var ctJson []byte

func processPT() {
	// decode all the base64 trash into byte slices for encrypting
	ptArray = make([][]byte, len(ptBase64Array))
	for i, pt := range ptBase64Array {
		tmp, err := base64.StdEncoding.DecodeString(pt)
		if err != nil {
			panic(err)
		}
		ptArray[i] = tmp
	}

	// get a random key and a fixed nonce of 0
	key := challenge11.GenerateRandomKey()
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	// encrypt everything
	ctArray := make([][]byte, len(ptArray))
	for i, pt := range ptArray {
		ctArray[i] = challenge18.CTR(pt, key, nonce)
	}

	ctJsonStruct = CTJsonStruct{
		CT: ctArray,
	}

	tmp, err := json.Marshal(ctJsonStruct)
	if err != nil {
		panic(err)
	}

	ctJson = tmp

	fmt.Println("Plaintext array processed, ciphertext array hydrated.")
}

func checkPt(got []string, wanted [][]byte) bool {
	if len(got) != len(wanted) {
		return false
	}
	for i, pt := range got {
		if !bytes.Equal([]byte(pt), wanted[i]) {
			fmt.Println("<<mismatch:>>", pt, "<<should have been:>>", string(wanted[i]))
			return false
		}
	}
	return true
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// path relative to main.go
	http.ServeFile(w, r, "set3/challenge19/index.html")
}

func ctHandler(w http.ResponseWriter, r *http.Request) {
	// send JSON ciphertext array
	io.WriteString(w, string(ctJson))
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	// see if challenge was solved
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&ptJsonStruct)

	if checkPt(ptJsonStruct.PT, ptArray) {
		io.WriteString(w, `{"success": "true"}`)
	} else {
		io.WriteString(w, `{"success": "false"`)
	}
}

func CrackServer() {
	processPT()
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/ct", ctHandler)
	http.HandleFunc("/check", checkHandler)
	http.ListenAndServe(":8000", nil)
}
