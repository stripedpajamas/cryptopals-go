package challenge21

// Mersenne Twister 19937

// thanks wikipedia <3

// constants:
var n, m int = 624, 397
var w, r uint = 32, 31
var a int = 0x9908B0DF
var u, s, t uint = 11, 7, 15
var d = 0xFFFFFFFF
var b = 0x9D2C5680
var c = 0xEFC60000
var l = 18
var f = 1812433253

// Create a length n array to store the state of the generator
var MT []int = make([]int, n)
var index int = n + 1
var lowerMask int = (1 << r) - 1
var upperMask int = leastSignificantBits(^lowerMask)

func leastSignificantBits(x int) int {
	return 0xFFFFFFFF & x
}

func Seed(seed int) {
	index = n
	MT[0] = seed
	for i := 1; i < n; i++ {
		MT[i] = leastSignificantBits(f*(MT[i-1]^(MT[i-1]>>(w-2))) + 1)
	}
}

func twist() {
	for i := 0; i < n; i++ {
		x := (MT[i] & upperMask) + (MT[(i+1)%n] & lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA & a
		}
		MT[i] = MT[(i+m)%n] ^ xA
	}
	index = 0
}

func Extract() int {
	if index >= n {
		if index > n {
			panic("Generator was not seeded")
		}
		twist()
	}

	y := MT[index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> 1)

	index++

	return leastSignificantBits(y)
}
