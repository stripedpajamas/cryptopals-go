package challenge52

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/stripedpajamas/cryptopals/set1/challenge7"
)

type Collision struct {
	a []byte
	b []byte
	h []byte
}

// Pad makes input a multiple of 16 bytes
func Pad(input []byte) []byte {
	// Padding. Add a 1 bit and 0 bits
	pad := new(bytes.Buffer)
	length := len(input)
	var tmp [16]byte
	tmp[0] = 0x80
	if length%16 < 8 {
		pad.Write(tmp[0 : 8-length%16])
	} else {
		pad.Write(tmp[0 : 16+8-length%16])
	}

	// Length in bits.
	length <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(length >> (8 * i))
	}
	pad.Write(tmp[0:8])

	output := make([]byte, len(input))
	copy(output, input)
	return append(output, pad.Bytes()...)
}

func CheapestHashEver(message, initialState []byte) []byte {
	// Merkle-Damgard construction
	// 1. pad the message to block size of 'compressor'
	// 2. set an initial h value
	// 3. for each block, set new h = C(m[i], previous_h)
	// 4. run out of blocks, return h

	// we're only going to be encrypting one block at a time
	// we'll use aes in ecb mode

	input := Pad(message)
	// var input []byte
	// if len(message)%16 > 0 {
	// 	input = challenge9.Pad(message, 16)
	// } else {
	// 	input = message
	// }

	h := initialState

	for i := 0; i < len(input); i += 16 {
		currentBlock := input[i : i+16]

		// h needs to be the 'key' for the encryption, so we'll need to make it 16 bytes long
		hKey := Pad(h)
		// hKey := challenge9.Pad(h, 16)
		enc := challenge7.ECBEncrypter(currentBlock, hKey)

		// our hash is only 2 bytes, so trim the output to the 2 most significant
		h = enc[:2]
	}

	return h
}

func CheapHash(message, initialState []byte) []byte {
	// same as cheapest, but is a 3-byte hash instead of 2-bytes
	input := Pad(message)
	// var input []byte
	// if len(message)%16 > 0 {
	// 	input = challenge9.Pad(message, 16)
	// } else {
	// 	input = message
	// }
	h := initialState
	for i := 0; i < len(input); i += 16 {
		currentBlock := input[i : i+16]
		hKey := Pad(h)
		// hKey := challenge9.Pad(h, 16)
		enc := challenge7.ECBEncrypter(currentBlock, hKey)
		h = enc[:3]
	}
	return h
}

func BeefyHash(input, initialState []byte) []byte {
	// returns the 5-byte hash of cheapest || cheap
	var output []byte
	output = append(output, CheapestHashEver(input, initialState)...)
	output = append(output, CheapHash(input, initialState)...)

	return output
}

func CheapestCollisionMachine(initialState []byte) *Collision {
	rand.Seed(time.Now().Unix())
	var collision *Collision
	hashes := make(map[string][]byte)
	for {
		a, b := make([]byte, 4), make([]byte, 4)
		for bytes.Equal(a, b) {
			rand.Read(a)
			rand.Read(b)
		}
		h, h2 := CheapestHashEver(a, initialState), CheapestHashEver(b, initialState)
		hs, hs2 := fmt.Sprintf("%0x", h), fmt.Sprintf("%0x", h2)

		if val, found := hashes[hs]; found {
			// a's hash is already in the map
			if !bytes.Equal(a, val) {
				// wouldn't be much of a collision if the inputs were the same
				collision = &Collision{a: a, b: val, h: h}
				break
			}
		} else if val, found := hashes[hs2]; found {
			// b's hash is already in the map
			if !bytes.Equal(a, val) {
				// wouldn't be much of a collision if the inputs were the same
				collision = &Collision{a: val, b: b, h: h2}
				break
			}
		} else {
			// nothing in the map yet, so update it with the new values
			hashes[hs] = a
			hashes[hs2] = b
		}

		// might as well see if h(a) = h(b) while we're here
		if bytes.Equal(h, h2) {
			collision = &Collision{a, b, h}
			break
		}
	}

	return collision
}

func FindCheapestCollisions(n int) [][]byte {
	var collisions [][]byte
	initialState := []byte("hi")
	fullCollisionLength := int(math.Pow(2, float64(n)))

	for len(collisions) < fullCollisionLength {
		collision := CheapestCollisionMachine(initialState)
		initialState = collision.h

		// update our wild multicollisions array
		newCollisions := [][]byte{}

		if len(collisions) > 0 {
			for _, c := range collisions {
				cola := Pad(c)
				colb := Pad(c)
				// cola := challenge9.Pad(c, 16)
				// colb := challenge9.Pad(c, 16)
				cola = append(cola, collision.a...)
				colb = append(colb, collision.b...)
				newCollisions = append(newCollisions, cola, colb)
			}
		} else {
			newCollisions = [][]byte{collision.a, collision.b}
		}
		collisions = newCollisions
	}

	return collisions
}

func FindMultiCollision() *Collision {
	// 	Pick the "cheaper" hash function (chepeast)
	//  Generate 2^(b2/2) colliding messages in it (2^12 colliding messages)
	//  There's a good chance your message pool has a collision in cheap.
	//  Find it.
	initialState := []byte("hi")
	cheapHashes := make(map[string][]byte)

	var multiCollision *Collision

	for multiCollision == nil {
		collisions := FindCheapestCollisions(12)

		for _, collision := range collisions {
			h := CheapHash(collision, initialState)
			hs := fmt.Sprintf("%0x", h)

			if val, found := cheapHashes[hs]; found {
				// this hash is already in the map
				if !bytes.Equal(collision, val) {
					if bytes.Equal(CheapestHashEver(collision, initialState), CheapestHashEver(val, initialState)) {
						multiCollision = &Collision{a: collision, b: val, h: h}
						break
					}
				}
			} else {
				// hash isn't in the map yet, so update it
				cheapHashes[hs] = collision
			}
		}
	}

	return multiCollision
}
