package challenge1

import (
	"encoding/base64"
	"encoding/hex"
)

func Hex2b64(hexString string) string {
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(hexBytes)
}
