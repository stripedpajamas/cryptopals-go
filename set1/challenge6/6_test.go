package challenge6

import (
	"testing"
	"io/ioutil"
	"fmt"
	"encoding/base64"
)

func TestHammingDistance(t *testing.T) {
	c6inputA := []byte("this is a test")
	c6inputB := []byte("wokka wokka!!!")
	c6ExpectedOutput := 37

	c6output := HammingDistance(c6inputA, c6inputB)

	if c6output != c6ExpectedOutput {
		t.Fail()
	}
}

func TestCrackRepeatingKeyXor(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/6
	encodedBytes, err := ioutil.ReadFile("6.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	decodedBytes, err := ioutil.ReadFile("6_decoded.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	ciphertextBytes := make([]byte, len(encodedBytes))
	bytesWritten, err := base64.StdEncoding.Decode(ciphertextBytes, encodedBytes)
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}

	ciphertextBytes = ciphertextBytes[:bytesWritten]

	c6output := CrackRepeatingKeyXor(ciphertextBytes)

	if c6output.text != string(decodedBytes) {
		t.Fail()
	}
}

var benchmarkResult Cracked

func BenchmarkCrackRepeatingKeyXor(b *testing.B) {
	// set up
	encodedBytes, err := ioutil.ReadFile("6.txt")
	if err != nil {
		fmt.Println("Error:", err)
		b.Fail()
	}

	ciphertextBytes := make([]byte, len(encodedBytes))
	bytesWritten, err := base64.StdEncoding.Decode(ciphertextBytes, encodedBytes)
	if err != nil {
		fmt.Println("Error:", err)
		b.Fail()
	}
	ciphertextBytes = ciphertextBytes[:bytesWritten]

	var c6output Cracked
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c6output = CrackRepeatingKeyXor(ciphertextBytes)
	}

	benchmarkResult = c6output
}