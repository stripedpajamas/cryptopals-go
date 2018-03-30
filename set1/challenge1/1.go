package challenge1

import (
	"encoding/base64"
	"encoding/hex"
)

// Hex2b64 converts a string of hex encoded bytes (e.g. deadbeef)
// into a string of its Base64 representation
func Hex2b64(hexString string) (string, error) {
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hexBytes), nil
}
