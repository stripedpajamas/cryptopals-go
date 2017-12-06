package challenge38

// a simplified SRP

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// the server
type SRPServer struct {
	N    *big.Int
	g    *big.Int
	k    *big.Int
	I    []byte // email
	P    []byte // password
	Salt *big.Int
	v    *big.Int
	B    *big.Int
	S    *big.Int
	K    [32]byte
}

// the client
type SRPClient struct {
	N    *big.Int
	g    *big.Int
	k    *big.Int
	Salt *big.Int
	A    *big.Int
	S    *big.Int
	K    [32]byte
}

/**
Server Methods
*/
func (server *SRPServer) Initialize(N, g, k *big.Int, email, password []byte) {
	// Initialize sets N, g, k, I, P
	// and then sets v = g^x mod N
	server.N, server.g, server.k, server.I, server.P = N, g, k, email, password

	// 1. Generate salt as random integer
	// 2. Generate string xH=SHA256(salt|password)
	// 3. Convert xH to integer x
	// 4. Generate v=g**x % N
	// 5. Save everything but x, xH

	saltBytes := make([]byte, 16)
	_, err := rand.Read(saltBytes)
	if err != nil {
		panic(err)
	}
	salt := new(big.Int)
	salt.SetBytes(saltBytes)

	xH := sha256.Sum256(append(salt.Bytes(), server.P...))
	x := new(big.Int)
	x.SetBytes(xH[:])

	v := new(big.Int)
	v.Exp(server.g, x, server.N)

	server.Salt = salt
	server.v = v
}

func (server *SRPServer) GetPublic(b *big.Int) *big.Int {
	// generates B = g^b mod N
	// this is the simplified part
	B := new(big.Int)
	B.Exp(server.g, b, server.N) // g^b % N

	server.B = B

	return B
}

func (server *SRPServer) GetSession(A, b, u *big.Int) [32]byte {
	// u is generated outside the protocol now, a random big number (128 bits)

	// generates S = (Av^u)^b mod N
	S := new(big.Int)
	tmp := new(big.Int)
	tmp.Exp(server.v, u, server.N) // v**u
	tmp.Mul(A, tmp)                // Av^u

	S.Exp(tmp, b, server.N)

	server.S = S

	server.K = sha256.Sum256(S.Bytes())

	return server.K
}

/**
Client Methods
*/
func (client *SRPClient) Initialize(N, g, k *big.Int) {
	client.N, client.g, client.k = N, g, k
}

func (client *SRPClient) SetSalt(salt *big.Int) {
	// sets the salt as received from the server
	client.Salt = salt
}

func (client *SRPClient) GetPublic(a *big.Int) *big.Int {
	// generates A = g^a mod N
	A := new(big.Int)
	A.Exp(client.g, a, client.N)

	client.A = A

	return A
}

func (client *SRPClient) GetSession(B, a, u *big.Int, password []byte) [32]byte {
	// 1. Generate string xH=SHA256(salt|password)
	// 2. Convert xH to integer x
	// 3. Generate S = B**(a + ux) % N
	// 4. Generate K = SHA256(S)

	xH := sha256.Sum256(append(client.Salt.Bytes(), password...))
	x := new(big.Int)
	x.SetBytes(xH[:])

	S := new(big.Int)
	tmp2 := new(big.Int)
	tmp2.Mul(u, x)           // ux
	tmp2.Add(a, tmp2)        // a + u * x
	S.Exp(B, tmp2, client.N) // B^(a + ux) % N

	client.S = S
	client.K = sha256.Sum256(S.Bytes())

	return client.K
}
