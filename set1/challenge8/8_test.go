package challenge8

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestDetectECB(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/8
	encodedBytes, err := ioutil.ReadFile("8.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	// we have bytes from the file, we'll split them up by line
	byteLines := bytes.Split(encodedBytes, []byte("\n"))

	// and convert each line to hex
	hexSlices := make([][]byte, len(byteLines))
	for i, byteLine := range byteLines {
		hexSlices[i] = make([]byte, len(byteLine)/2)
		hex.Decode(hexSlices[i], byteLine)
	}

	c8output := DetectECB(hexSlices)

	// the ECB encrypted ciphertext is on line 133
	if bytes.Compare(c8output[0], hexSlices[132]) != 0 {
		t.Fail()
	}
}
