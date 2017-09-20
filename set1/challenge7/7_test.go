package challenge7

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestECBDecrypter(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/7
	encodedBytes, err := ioutil.ReadFile("7.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	decodedBytes, err := ioutil.ReadFile("7_decoded.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	// pad the decoded file with PKCS#7 padding because that's how it will end up
	// after decoding with ECB
	decodedBytes = append(decodedBytes, 4, 4, 4, 4)

	ciphertextBytes := make([]byte, len(encodedBytes))
	bytesWritten, err := base64.StdEncoding.Decode(ciphertextBytes, encodedBytes)
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	ciphertextBytes = ciphertextBytes[:bytesWritten]

	c7output := ECBDecrypter(ciphertextBytes, []byte("YELLOW SUBMARINE"))

	if string(c7output) != string(decodedBytes) {
		t.Fail()
	}
}

func TestECBEncrypter(t *testing.T) {
	// just confirm that an encryption of the plaintext of
	// http://cryptopals.com/sets/1/challenges/7 ends up being the same

	plaintext, err := ioutil.ReadFile("7_decoded.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}
	plaintext = append(plaintext, 4, 4, 4, 4)

	ciphertext, err := ioutil.ReadFile("7.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	ciphertextBytes := make([]byte, len(ciphertext))
	bytesWritten, err := base64.StdEncoding.Decode(ciphertextBytes, ciphertext)
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	ciphertextBytes = ciphertextBytes[:bytesWritten]

	c7output := ECBEncrypter(plaintext, []byte("YELLOW SUBMARINE"))

	if bytes.Compare(c7output, ciphertextBytes) != 0 {
		t.Fail()
	}
}
