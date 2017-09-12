package challenge1

import (
	"errors"
	"encoding/hex"
	"encoding/base64"
)

func Hex2b64(hexString string) (string, error) {
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", errors.New("Failed to convert hex string to bytes")
	}

	return base64.StdEncoding.EncodeToString(hexBytes), nil
}
