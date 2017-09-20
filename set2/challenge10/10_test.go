package challenge10

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestCBCDecrypter(t *testing.T) {
	// http://cryptopals.com/sets/2/challenges/10
	encodedBytes, err := ioutil.ReadFile("10.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	decodedBytes, err := ioutil.ReadFile("10_decoded.txt")
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

	c10inputIV := bytes.Repeat([]byte{0}, 16)
	c10inputKey := []byte("YELLOW SUBMARINE")

	c10output := CBCDecrypter(c10inputIV, ciphertextBytes, c10inputKey)

	if bytes.Compare(c10output, decodedBytes) != 0 {
		t.Fail()
	}
}

func TestCBCEncrypter(t *testing.T) {
	c10input := []byte("hello world! have some vegan meatballs for lunch")
	c10inputIV := bytes.Repeat([]byte{0}, 16)
	c10inputKey := []byte("who killed puck?")

	c10encrypted := CBCEncrypter(c10inputIV, c10input, c10inputKey)

	if bytes.Compare(c10input, CBCDecrypter(c10inputIV, c10encrypted, c10inputKey)) != 0 {
		t.Fail()
	}
}
