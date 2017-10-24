package challenge23

import "github.com/stripedpajamas/cryptopals/set3/challenge21"

func Untemper(y int) int {
	/*
			this is what MT does internally when Extract() is called:

			y := MT[index]
			y = y ^ (y >> 11)
			y = y ^ ((y << 7) & 0x9D2C5680)
			y = y ^ ((y << 15) & 0xEFC60000)
			y = y ^ (y >> 18)

			return 0xFFFFFFFF & y (which doesn't really do anything I think)

			we just need to do the inverse in reverse
		  i found that looping some of the tempering steps eventually gives the original
	*/

	y = y ^ (y >> 18)
	y = y ^ ((y << 15) & 0xEFC60000)

	for i := 0; i < 7; i++ {
		y = y ^ ((y << 7) & 0x9D2C5680)
	}

	for i := 0; i < 3; i++ {
		y = y ^ (y >> 11)
	}

	return y
}

func CloneMT(MT challenge21.MT19937) challenge21.MT19937 {
	// make our own instance
	myMT := challenge21.NewMT19937()

	// tap 624 values and then untemper them all
	for i := 0; i < myMT.N; i++ {
		myMT.State[i] = Untemper(MT.Extract())
	}

	// since 624 values have been tapped, run the twist
	myMT.Twist()

	// return extract func
	return myMT
}
