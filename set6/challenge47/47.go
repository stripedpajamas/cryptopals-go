package challenge47

import (
	"fmt"
	"math/big"

	"github.com/stripedpajamas/cryptopals/set5/challenge39"
)

type Interval struct {
	a *big.Int
	b *big.Int
}

var rsa = challenge39.RSA{}
var OracleCalls = 0
var Verbose = false

func init() {
	rsa.Initialize(256)
}

// Oracle returns true if the decrypted ciphertext has valid padding
// valid meaning pt[0] = 0, pt[1] = 2 (at least for now)
func Oracle(ciphertext []byte) bool {
	OracleCalls++
	pt := rsa.Decrypt(ciphertext)
	// append a 0 to account for the translation from numbers into bytes
	pt = append([]byte{0}, pt...)

	return pt[0] == 0 && pt[1] == 2
}

// FindLowestS searches for the smallest s value larger than lowerbound
// such that c0(s^e) mod n is PKCS conforming
// gte specifies whether the s search should start >= lowerbound if true, > lowerbound if false
func FindLowestS(lowerBound, N, E, C *big.Int, gte bool, PKCSOracle func([]byte) bool) *big.Int {
	big1 := big.NewInt(1)
	possibleS := new(big.Int).Set(lowerBound)
	if !gte {
		possibleS.Add(big1, possibleS)
	}
	sEnc := new(big.Int)
	sEnc.Exp(possibleS, E, N).Mul(sEnc, C).Mod(sEnc, N)

	// increment s until c0 * s^e mod n is PKCS valid
	for !PKCSOracle(sEnc.Bytes()) {
		possibleS.Add(possibleS, big1)
		sEnc.Exp(possibleS, E, N).Mul(sEnc, C).Mod(sEnc, N)
	}

	return possibleS
}

func BB98(ct []byte, N, E *big.Int, PKCSOracle func([]byte) bool) []byte {
	if N.BitLen()%8 != 0 {
		panic("N length must be multiple of 8")
	}
	// step 1: setup
	i := 1
	// inital c is ct
	c := new(big.Int).SetBytes(ct)
	sValues := make([]*big.Int, 1)
	MValues := make([][]*Interval, 1)

	rem := new(big.Int) // for remainders
	big1 := big.NewInt(1)
	big2 := big.NewInt(2)
	big3 := big.NewInt(3)

	k := int64(len(N.Bytes()))
	B := big.NewInt(2)
	B.Exp(B, big.NewInt(8*(k-2)), nil)
	B2 := new(big.Int).Mul(big2, B)
	B3 := new(big.Int).Mul(big3, B)

	// initial s is 1
	sValues[0] = big1
	// initial M contains the interval 2B,3B-1
	MValues[0] = make([]*Interval, 1)
	MValues[0][0] = &Interval{
		a: B2,
		b: new(big.Int).Sub(B3, big1),
	}

	// step 3: update M[i]
	// for each Interval in M[i-1], compute a range of r values
	// and from those r values compute new Intervals to add to M[i]
	updateMValues := func() {
		MValues = append(MValues, make([][]*Interval, 1)...)
		r, rLow, rHigh := new(big.Int), new(big.Int), new(big.Int)
		newA, newB := new(big.Int), new(big.Int)

		for _, interval := range MValues[i-1] {
			// rLow = (a*s - 3B + 1) / n
			// rHigh = (b*s - 2B) / n
			rLow.Mul(interval.a, sValues[i]).Sub(rLow, B3).Add(rLow, big1)
			rLow.DivMod(rLow, N, rem)
			if rem.Sign() > 0 {
				rLow.Add(rLow, big1)
			}

			rHigh.Mul(interval.b, sValues[i]).Sub(rHigh, B2).Div(rHigh, N)
			// we can take the floor of this division since it's the high val

			for r.Set(rLow); r.Cmp(rHigh) <= 0; r.Add(r, big1) {
				// newA is max(a, ceiling (2B + rn / s))
				// newB is min(b, floor (3B - 1 + rn / s))
				// big ints floor division by default, so we will just add 1 when doing ceiling
				newA.Mul(r, N).Add(B2, newA)
				newA.DivMod(newA, sValues[i], rem)
				if rem.Sign() > 0 {
					newA.Add(newA, big1) // ceiling
				}
				if newA.Cmp(interval.a) < 0 {
					// newA < a, keep the old a (want the max)
					newA.Set(interval.a)
				}

				newB.Mul(r, N).Add(B3, newB).Sub(newB, big1).Div(newB, sValues[i])
				if newB.Cmp(interval.b) > 0 {
					// newB > b, keep the old b (want the min)
					newB.Set(interval.b)
				}

				MValues[i] = append(MValues[i], &Interval{a: newA, b: newB})
			}
		}
	}

	for {
		// step 2
		// step 2.a (if i = 1)
		if i == 1 {
			// find smallest s >= n/3B
			lowerBound := new(big.Int)
			lowerBound.DivMod(N, B3, rem)
			if rem.Sign() > 0 {
				lowerBound.Add(lowerBound, big1)
			}
			newS := FindLowestS(lowerBound, N, E, c, true, PKCSOracle)
			sValues = append(sValues, newS)
		} else {
			// step 2.c
			// only one interval in the previous M set
			// start looking at small r values,
			// compute the resulting s values, until one is PKCS conforming

			r, sLow, sHigh, possibleS, sEnc := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)

			// 2 * ( bs − 2B ) / N
			r.Mul(MValues[i-1][0].b, sValues[i-1]).Sub(r, B2).Mul(r, big2)
			r.DivMod(r, N, rem)
			if rem.Sign() > 0 {
				r.Add(r, big1)
			}

		searchLoop:
			for {
				// ( 2B + rn ) / b
				sLow.Mul(r, N).Add(sLow, B2)
				sLow.DivMod(sLow, MValues[i-1][0].b, rem)
				if rem.Sign() > 0 {
					sLow.Add(sLow, big1)
				}

				// ( 3B + rn ) / a
				sHigh.Mul(r, N).Add(sHigh, B3)
				sHigh.DivMod(sHigh, MValues[i-1][0].a, rem)
				if rem.Sign() > 0 {
					sHigh.Add(sHigh, big1)
				}

				possibleS.Set(sLow)

				for possibleS.Cmp(sHigh) < 0 {
					sEnc.Exp(possibleS, E, N).Mul(sEnc, c).Mod(sEnc, N)
					if PKCSOracle(sEnc.Bytes()) {
						break searchLoop
					}
					possibleS.Add(possibleS, big1)
				}
				// now that s has reached its bound, increment r and reset sHigh/sLow
				r.Add(r, big1)
			}
			// if we've escaped the loop, we've found a new s value
			sValues = append(sValues, possibleS)
		}

		updateMValues()

		for len(MValues[i]) != 1 {
			// step 2.b
			// find smallest s > previous s
			newS := FindLowestS(sValues[i-1], N, E, c, false, PKCSOracle)
			sValues = append(sValues, newS)
			updateMValues()
		}

		if Verbose {
			fmt.Printf("%x\n", MValues[i][0].a.Bytes())
		}

		// step 4: if M[i] has only 1 interval and a=b in that interval
		if MValues[i][0].a.Cmp(MValues[i][0].b) == 0 {
			if Verbose {
				fmt.Printf("Recovery complete after %d calls to the oracle\n", OracleCalls)
			}
			return MValues[i][0].a.Bytes()
		}
		// otherwise i++
		i++
	}
}
