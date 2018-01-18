package challenge49

import (
	"bytes"
	"net/url"
	"strconv"
)

type ServerV1 struct {
	key []byte
}

type TransferRequestV1 struct {
	message []byte
	iv      []byte
	mac     []byte
}

type TransferResponse struct {
	success bool
	to      int
	from    int
	amount  int
}

func (s *ServerV1) Transfer(t *TransferRequestV1) TransferResponse {
	// server first checks MAC on message
	mac := CBCMAC(t.message, t.iv, s.key)

	if bytes.Equal(mac, t.mac) {
		// signature verified, do the transaction
		vals, err := url.ParseQuery(string(t.message))
		if err != nil {
			// problems with message, send back success false
			return TransferResponse{
				success: false,
			}
		}

		to, err := strconv.Atoi(vals.Get("to"))
		from, err2 := strconv.Atoi(vals.Get("from"))
		amount, err3 := strconv.Atoi(vals.Get("amount"))

		if err != nil || err2 != nil || err3 != nil {
			return TransferResponse{
				success: false,
			}
		}

		// ... bank logic goes here
		// ...
		// send back confirmation
		return TransferResponse{
			success: true,
			to:      to,
			from:    from,
			amount:  amount,
		}
	}

	// mac is bad, success is false
	return TransferResponse{
		success: false,
	}
}
