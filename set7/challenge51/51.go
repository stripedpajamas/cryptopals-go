package challenge51

import (
	"bytes"
	"compress/zlib"
	"fmt"

	"github.com/stripedpajamas/cryptopals/set2/challenge9"

	"github.com/stripedpajamas/cryptopals/set2/challenge10"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set3/challenge18"
)

func CompressionOracle(pt []byte, stream bool) int {
	// random key+IV for every call
	iv := challenge11.GenerateRandomKey()
	nonce := iv[:8]
	key := challenge11.GenerateRandomKey()

	// format request like this:
	//  POST / HTTP/1.1
	//  Host: hapless.com
	//  Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
	//  Content-Length: ((len(P)))
	//  ((P))

	partialFormat := "POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
	formatted := fmt.Sprintf("%sContent-Length: %d\n%s", partialFormat, len(pt), string(pt))

	input := []byte(formatted)

	// compress the formatted input
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	w.Write(input)
	w.Close()

	var enc []byte

	if stream {
		// use a stream cipher
		enc = challenge18.CTR(compressed.Bytes(), key, nonce)
	} else {
		// use a block cipher
		plaintext := challenge9.Pad(compressed.Bytes(), 16)
		enc = challenge10.CBCEncrypter(iv, plaintext, key)
	}

	return len(enc)
}

func GuessSessionKeyStream(verbose bool) []byte {
	recoveredSessionID := []byte("sessionid=")
	var currentWinner int
	for sessionIdx := 0; currentWinner != 10; sessionIdx++ {
		currentTarget := append(recoveredSessionID, 0)
		currentScore := CompressionOracle(currentTarget, true)
		currentWinner = 0

		for i := 1; i < 255; i++ {
			currentTarget = append(recoveredSessionID, byte(i))
			currentCompression := CompressionOracle(currentTarget, true)
			if currentCompression < currentScore {
				currentScore = currentCompression
				currentWinner = i
			}
		}

		recoveredSessionID = append(recoveredSessionID, byte(currentWinner))
		if verbose {
			fmt.Println(string(recoveredSessionID))
		}
	}

	return recoveredSessionID
}

func GuessSessionKeyBlock(verbose bool) []byte {
	workingThing := []byte("Host: hapless.com\nCookie: sessionid=")
	recoveredSessionID := []byte("sessionid=")
	var currentWinner int

	for sessionIdx := 0; currentWinner != 10; sessionIdx++ {
		temporaryInsanity := append([]byte("ö÷øùúûx"), workingThing...)
		currentTarget := append(temporaryInsanity, 0)
		currentScore := CompressionOracle(currentTarget, false)
		currentWinner = 0

		for i := 1; i < 255; i++ {
			currentTarget = append(temporaryInsanity, byte(i))
			currentCompression := CompressionOracle(currentTarget, false)
			if currentCompression < currentScore {
				currentScore = currentCompression
				currentWinner = i
			}
		}

		workingThing = append(workingThing, byte(currentWinner))
		recoveredSessionID = append(recoveredSessionID, byte(currentWinner))
		if verbose {
			fmt.Println(string(recoveredSessionID))
		}
	}

	return recoveredSessionID
}
