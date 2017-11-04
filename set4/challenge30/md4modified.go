// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md4 implements the MD4 hash algorithm as defined in RFC 1320.
package challenge30

// The size of an MD4 checksum in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	//_Init0 = 0x67452301
	//_Init1 = 0xEFCDAB89
	//_Init2 = 0x98BADCFE
	//_Init3 = 0x10325476
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset(h0, h1, h2, h3 uint32) {
	d.s[0] = h0
	d.s[1] = h1
	d.s[2] = h2
	d.s[3] = h3
	d.nx = 0
	d.len = 0
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte, desiredLen int) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(digest)
	*d = *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	//len := d.len
	len := desiredLen
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

// Sum returns the MD4 checksum of the data.
func Sum(data []byte, h0, h1, h2, h3 uint32, desiredLen int) []byte {
	var d digest
	d.Reset(h0, h1, h2, h3)
	d.Write(data)
	return d.Sum(nil, desiredLen)
}
