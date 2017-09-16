package challenge4

import (
	"testing"
	"io/ioutil"
	"bytes"
	"fmt"
)

func TestDetectSingleKeyXor(t *testing.T) {
	// http://cryptopals.com/sets/1/challenges/4
	encodedStrings, err := ioutil.ReadFile("4.txt")
	if err != nil {
		fmt.Println("Error:", err)
		t.Fail()
	}
	// we have bytes from the file, we'll split them up by line
	byteLines := bytes.Split(encodedStrings, []byte("\n"))

	// and convert each line to a hex string to pass to the Detector
	hexSlices := make([]string, len(byteLines))
	for i, byteLine := range byteLines {
		hexSlices[i] = string(byteLine)
	}

	c4expectedOutput := "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
	c4expectedText := "Now that the party is jumping\n"
	c4output := DetectSingleKeyXor(hexSlices)

	if c4output.original != c4expectedOutput || c4output.processed.Text != c4expectedText {
		t.Fail()
	}
}

var benchmarkResult *Identified

func BenchmarkDetectSingleKeyXor(b *testing.B) {
	// set up
	// http://cryptopals.com/sets/1/challenges/4
	encodedStrings, err := ioutil.ReadFile("4.txt")
	if err != nil {
		fmt.Println("Error:", err)
		b.Fail()
	}
	// we have bytes from the file, we'll split them up by line
	byteLines := bytes.Split(encodedStrings, []byte("\n"))

	// and convert each line to a hex string to pass to the Detector
	hexSlices := make([]string, len(byteLines))
	for i, byteLine := range byteLines {
		hexSlices[i] = string(byteLine)
	}

	var c4output *Identified
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c4output = DetectSingleKeyXor(hexSlices)
	}

	benchmarkResult = c4output
}
