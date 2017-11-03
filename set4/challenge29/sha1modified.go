package challenge29

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

const (
	chunk = 64
	//init0 = 0x67452301
	//init1 = 0xEFCDAB89
	//init2 = 0x98BADCFE
	//init3 = 0x10325476
	//init4 = 0xC3D2E1F0
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset(h0, h1, h2, h3, h4 uint32) {
	d.h[0] = h0
	d.h[1] = h1
	d.h[2] = h2
	d.h[3] = h3
	d.h[4] = h4
	d.nx = 0
	d.len = 0
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			blockGeneric(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		blockGeneric(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) checkSum(desiredLen int) [Size]byte {
	len := desiredLen
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
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
		tmp[i] = byte(len >> (56 - 8*i))
	}
	d.Write(tmp[0:8])

	//if d.nx != 0 {
	//	panic("d.nx != 0")
	//}

	var digest [Size]byte
	for i, s := range d.h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}

	return digest
}

// Sum returns the SHA-1 checksum of the data.
func Sum(data []byte, h0, h1, h2, h3, h4 uint32, desiredLen int) [Size]byte {
	var d digest
	d.Reset(h0, h1, h2, h3, h4)
	d.Write(data)
	return d.checkSum(desiredLen)
}
