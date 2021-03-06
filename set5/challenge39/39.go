package challenge39

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type RSA struct {
	N *big.Int
	E *big.Int
	d *big.Int
}

var HashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:    {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func GetPrimes(bitlen int) (p, q, a, b *big.Int) {
	// returns two big primes and their respective minus ones
	// a = p-1
	// b = q-1
	p, err := rand.Prime(rand.Reader, bitlen/2)
	if err != nil {
		panic(err)
	}
	q, err = rand.Prime(rand.Reader, bitlen/2)
	if err != nil {
		panic(err)
	}

	a = new(big.Int).Sub(p, big.NewInt(1))
	b = new(big.Int).Sub(q, big.NewInt(1))

	return p, q, a, b
}

func (r *RSA) Initialize(bitlen int) {
	big1 := big.NewInt(1)
	p, q, a, b := GetPrimes(bitlen)
	r.E = big.NewInt(3)          // e = 3
	et := new(big.Int).Mul(a, b) // et = (p-1)(q-1)
	tmp := new(big.Int)

	// e must be coprime with (p-1)(q-1)
	for tmp.GCD(nil, nil, r.E, et).Cmp(big1) != 0 {
		p, q, a, b = GetPrimes(bitlen)
		et = new(big.Int).Mul(a, b)
	}

	r.N = new(big.Int).Mul(p, q)           // N = pq
	r.d = new(big.Int).ModInverse(r.E, et) // de == 1 (mod totient(n))
}

func (r *RSA) Pad(input []byte, N *big.Int) ([]byte, error) {
	// PKCS#1, something like 00:02:PADDINGSTRING:00:DATABLOCK
	NByteLen := len(N.Bytes())
	inputLen := len(input)

	// input length must not exceed byte length of N - 11
	if inputLen > NByteLen-11 {
		err := fmt.Sprintf("input too long for modulus: %d > %d", inputLen, NByteLen-11)
		return nil, errors.New(err)
	}

	paddingStringLen := NByteLen - 3 - inputLen
	paddingString := make([]byte, paddingStringLen)

	// need to fill padding string buffer with non-zero
	for idx, _ := range paddingString {
		r := make([]byte, 1)
		// get a random byte until it's non zero
		for r[0] == 0 {
			_, err := rand.Read(r)
			if err != nil {
				return nil, err
			}
		}
		paddingString[idx] = r[0]
	}

	// 00:02:PS:00:INPUT
	outputLen := 3 + paddingStringLen + inputLen
	output := make([]byte, outputLen)
	output[0] = 0
	output[1] = 2
	copy(output[2:], paddingString)
	output[2+paddingStringLen] = 0
	copy(output[paddingStringLen+3:], input)

	return output, nil
}

func (r *RSA) RemovePad(input []byte) []byte {
	// takes in a decrypted input and returns the stuff after the 00
	// 00:02:PS:00:RETURNME
	for idx := 2; idx < len(input); idx++ {
		if input[idx] == 0 {
			if idx == len(input)-1 {
				return []byte{}
			}
			return input[idx+1:]
		}
	}
	return []byte{}
}

func (r *RSA) EncryptWithPad(input []byte, N, E *big.Int) ([]byte, error) {
	padded, err := r.Pad(input, N)
	if err != nil {
		return nil, err
	}
	return r.Encrypt(padded, N, E), nil
}

func (r *RSA) Encrypt(input []byte, N, E *big.Int) []byte {
	m := new(big.Int).SetBytes(input)
	// encrypt: c = m**e%n
	return new(big.Int).Exp(m, r.E, r.N).Bytes()
}

func (r *RSA) Decrypt(input []byte) []byte {
	c := new(big.Int).SetBytes(input)
	// decrypt: m = c**d%n
	return new(big.Int).Exp(c, r.d, r.N).Bytes()
}

func (r *RSA) Sign(inputHash []byte, hash crypto.Hash) []byte {
	// assuming input hash is a hash made with the supplied hash function
	// then we prepend it with the asn.1 goop
	payload := append(HashPrefixes[hash], inputHash...)

	nLen := len(r.N.Bytes())
	payloadLen := len(payload)

	// 00 01 FF FF FF ... FF 00 PAYLOAD
	sigBlock := make([]byte, nLen)
	sigBlock[1] = 1
	// fill with FF
	for i := 2; i < nLen-payloadLen-1; i++ {
		sigBlock[i] = 0xff
	}
	copy(sigBlock[nLen-payloadLen:nLen], payload)

	// then apply 'd' to this block

	return r.Decrypt(sigBlock)
}

func (r *RSA) VerifySignature(N, e *big.Int, inputHash, sig []byte, hash crypto.Hash) bool {
	// N, e are from the sender
	// verification of signature is to apply the public exponent to the signature
	// that should produce 00 01 FF FF FF ... FF 00 PAYLOAD
	// where PAYLOAD = ASN.1 goop and the hash of the message
	// we can then check to make sure the asn.1 goop is correct, and then check
	// that our own hash of the plaintext matches the hash we find here

	// so first step is to apply the public exponent to the signature
	decSigInt := new(big.Int).SetBytes(sig)
	decSigInt.Exp(decSigInt, e, N)
	decSig := decSigInt.Bytes()
	// account for dropping the first zero
	decSig = append([]byte{0}, decSig...)

	// make a valid payload of asn.1 goop + hash of plaintext
	validPayload := append(HashPrefixes[hash], inputHash...)
	if len(decSig) < 4+len(validPayload) {
		return false
	}

	// do a dirty loop until we find the where the has begins
	// this is the 'implementation flaw' that we will exploit in 42
	if decSig[0] != 0 || decSig[1] != 1 {
		return false
	}

	payloadIdx := 0
	for i := 2; i < len(decSig); i++ {
		if decSig[i] != 0xFF {
			if decSig[i] == 0 {
				payloadIdx = i + 1
				break
			} else {
				return false
			}
		}
	}

	receivedPayload := decSig[payloadIdx : payloadIdx+len(HashPrefixes[hash])+hash.Size()]
	if !bytes.Equal(validPayload, receivedPayload) {
		return false
	}
	return true
}
