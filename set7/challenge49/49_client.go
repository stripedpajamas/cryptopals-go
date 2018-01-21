package challenge49

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
)

type ClientV1 struct {
	key      []byte
	account  int
	sendFunc func(*ServerV1, *TransferRequestV1) TransferResponseV1
}

type ClientV2 struct {
	key      []byte
	iv       []byte
	account  int
	sendFunc func(*ServerV2, *TransferRequestV2) TransferResponseV2
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

func (c *ClientV1) Transfer(to, amount int, server *ServerV1) TransferResponseV1 {
	values := url.Values{}
	values.Add("from", strconv.Itoa(c.account))
	values.Add("to", strconv.Itoa(to))
	values.Add("amount", strconv.Itoa(amount))
	// unfortunately the built-in encoding function sorts the strings alphabetically
	// which ruins this attack :(
	message := []byte(EncodeNoSort(values))
	paddedMessage := challenge9.Pad(message, 16)
	iv := challenge11.GenerateRandomKey()
	mac := CBCMAC(paddedMessage, iv, c.key)
	request := &TransferRequestV1{
		message: paddedMessage,
		iv:      iv,
		mac:     mac,
	}

	return c.sendFunc(server, request)
}

func (c *ClientV2) Transfer(txList []Transaction, server *ServerV2) TransferResponseV2 {
	// turn txList into querystring stuff
	txListStrings := []string{}
	for _, tx := range txList {
		txListStrings = append(txListStrings, fmt.Sprintf("%d:%d", tx.to, tx.amount))
	}

	values := url.Values{}
	values.Add("from", strconv.Itoa(c.account))
	values.Add("tx_list", strings.Join(txListStrings, ";"))

	// unfortunately the built-in encoding function sorts the strings alphabetically
	// which ruins this attack :(
	message := []byte(EncodeNoSort(values))
	paddedMessage := challenge9.Pad(message, 16)
	mac := CBCMAC(paddedMessage, c.iv, c.key)
	request := &TransferRequestV2{
		message: paddedMessage,
		mac:     mac,
	}

	return c.sendFunc(server, request)
}
