package challenge21

// Mersenne Twister 19937
// thanks wikipedia <3

type MT19937 struct {
	State                                         []int
	Index, lowerMask, upperMask, N, m, a, b, c, f int
	u, s, t, l, w, r                              uint
}

type PRNG interface {
	Seed(int)
	Twist()
	Extract() int
}

func NewMT19937() MT19937 {
	mt := MT19937{
		State: make([]int, 624),
		Index: 625,
		N:     624,
		m:     397,
		w:     32,
		r:     31,
		a:     0x9908B0DF,
		u:     11,
		s:     7,
		t:     15,
		l:     18,
		b:     0x9D2C5680,
		c:     0xEFC60000,
		f:     1812433253,
	}
	mt.lowerMask = (1 << mt.r) - 1
	mt.upperMask = 0xFFFFFFFF & (^mt.lowerMask)

	return mt
}

func (mt *MT19937) Seed(seed int) {
	mt.Index = mt.N
	mt.State[0] = seed
	for i := 1; i < mt.N; i++ {
		mt.State[i] = 0xFFFFFFFF & (mt.f*(mt.State[i-1]^(mt.State[i-1]>>(mt.w-2))) + 1)
	}
}

func (mt *MT19937) Twist() {
	for i := 0; i < mt.N; i++ {
		x := (mt.State[i] & mt.upperMask) + (mt.State[(i+1)%mt.N] & mt.lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA & mt.a
		}
		mt.State[i] = mt.State[(i+mt.m)%mt.N] ^ xA
	}
	mt.Index = 0
}

func (mt *MT19937) Extract() int {
	if mt.Index >= mt.N {
		if mt.Index > mt.N {
			panic("Generator was not seeded")
		}
		mt.Twist()
	}

	y := mt.State[mt.Index]
	y = y ^ (y >> mt.u)
	y = y ^ ((y << mt.s) & mt.b)
	y = y ^ ((y << mt.t) & mt.c)
	y = y ^ (y >> mt.l)

	mt.Index++

	return 0xFFFFFFFF & y
}
