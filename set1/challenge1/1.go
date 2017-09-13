package challenge1

import (
	"encoding/hex"
	"encoding/base64"
)

func Hex2b64(hexString string) string {
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(hexBytes)
}
