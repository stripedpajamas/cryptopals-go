package challenge49

import (
	"bytes"
	"net/url"
	"strconv"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
)

type ClientV1 struct {
	key      []byte
	account  int
	sendFunc func(*ServerV1, *TransferRequestV1) TransferResponse
}

func EncodeNoSort(v url.Values) string {
	if v == nil {
		return ""
	}
	var buf bytes.Buffer
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	for _, k := range keys {
		vs := v[k]
		prefix := url.QueryEscape(k) + "="
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(prefix)
			buf.WriteString(url.QueryEscape(v))
		}
	}
	return buf.String()
}

func (c *ClientV1) Transfer(to, amount int, server *ServerV1) TransferResponse {
	values := url.Values{
		"from":   []string{strconv.Itoa(c.account)},
		"to":     []string{strconv.Itoa(to)},
		"amount": []string{strconv.Itoa(amount)},
	}
	// unfortunately the built-in encoding function sorts the strings alphabetically
	// which ruins this attack :(
	message := []byte(EncodeNoSort(values))
	iv := challenge11.GenerateRandomKey()
	mac := CBCMAC(message, iv, c.key)
	request := &TransferRequestV1{
		message: message,
		iv:      iv,
		mac:     mac,
	}

	return c.sendFunc(server, request)
}
