package challenge49

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/stripedpajamas/cryptopals/set2/challenge15"
)

type ServerV1 struct {
	key []byte
}

type ServerV2 struct {
	key []byte
	iv  []byte
}

type TransferRequestV1 struct {
	message []byte
	iv      []byte
	mac     []byte
}
type TransferRequestV2 struct {
	message []byte
	mac     []byte
}

type TransferResponseV1 struct {
	success bool
	to      int
	from    int
	amount  int
}

type Transaction struct {
	to     int
	amount int
}

type TransferResponseV2 struct {
	success bool
	from    int
	txList  []Transaction
}

func (s *ServerV1) Transfer(t *TransferRequestV1) TransferResponseV1 {
	// server first checks MAC on message (using server static IV)
	mac := CBCMAC(t.message, t.iv, s.key)

	if bytes.Equal(mac, t.mac) {
		// signature verified, do the transaction
		unPadded, err := challenge15.RemoveValidPad(t.message, 16)
		if err != nil {
			// problems with message, send back success false
			return TransferResponseV1{
				success: false,
			}
		}
		vals, err := url.ParseQuery(string(unPadded))
		if err != nil {
			// problems with message, send back success false
			return TransferResponseV1{
				success: false,
			}
		}

		to, err := strconv.Atoi(vals.Get("to"))
		from, err2 := strconv.Atoi(vals.Get("from"))
		amount, err3 := strconv.Atoi(vals.Get("amount"))

		if err != nil || err2 != nil || err3 != nil {
			return TransferResponseV1{
				success: false,
			}
		}

		// ... bank logic goes here
		// ...
		// send back confirmation
		return TransferResponseV1{
			success: true,
			to:      to,
			from:    from,
			amount:  amount,
		}
	}

	// mac is bad, success is false
	return TransferResponseV1{
		success: false,
	}
}

func (s *ServerV2) Transfer(t *TransferRequestV2) TransferResponseV2 {
	// server first checks MAC on message
	mac := CBCMAC(t.message, s.iv, s.key)

	if bytes.Equal(mac, t.mac) {
		// signature verified, do the transaction
		unPadded, err := challenge15.RemoveValidPad(t.message, 16)
		if err != nil {
			fmt.Println("Error removing pad", err.Error())
			// problems with message, send back success false
			return TransferResponseV2{
				success: false,
			}
		}
		vals, err := url.ParseQuery(string(unPadded))
		if err != nil {
			fmt.Println("Error parsing QS", err.Error())
			// problems with message, send back success false
			return TransferResponseV2{
				success: false,
			}
		}

		from, err := strconv.Atoi(vals.Get("from"))
		if err != nil {
			fmt.Println("Error converting from address", err.Error())
			return TransferResponseV2{
				success: false,
			}
		}

		txListRaw := vals.Get("tx_list")
		txListStrings := strings.Split(txListRaw, ";")
		txList := []Transaction{}

		for _, tx := range txListStrings {
			split := strings.Split(tx, ":")
			to, _ := strconv.Atoi(split[0])
			amount, _ := strconv.Atoi(split[1])
			txList = append(txList, Transaction{to, amount})
		}

		// ... bank logic goes here
		// ...
		// send back confirmation
		return TransferResponseV2{
			success: true,
			from:    from,
			txList:  txList,
		}
	}

	// mac is bad, success is false
	return TransferResponseV2{
		success: false,
	}
}
