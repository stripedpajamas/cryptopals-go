package challenge40

import (
	"math/big"
)

func CubeRoot(m *big.Int) *big.Int {
	k := big.NewInt(3)
	u := new(big.Int).Set(m)
	s := new(big.Int).Add(u, k) // s = u + k
	two := big.NewInt(2)

	for u.Cmp(s) == -1 { // repeat while u < s
		s = new(big.Int).Set(u)
		ss := new(big.Int).Exp(s, two, nil) // s^2
		d := new(big.Int).Div(m, ss)        // m / s^2
		t := new(big.Int).Mul(two, s)       // 2s
		t.Add(t, d)                         // t = 2s + (m/s^2)
		u.Div(t, k)
	}

	return s
}

func DiscoverPlaintext(c0, c1, c2, n0, n1, n2 *big.Int) *big.Int {
	// discovering a single plaintext that was encrypted 3 times with 3 different pub keys
	// chinese remainder theorem helps apparently
	/*
				result =
				(c_0 * m_s_0 * invmod(m_s_0, n_0)) +
				(c_1 * m_s_1 * invmod(m_s_1, n_1)) +
				(c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

				m_s_n (for n in 0, 1, 2) are the product of the moduli
		 		EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
	*/
	// and then result (before doing mod N_012) = m^3, so take the cube root and you have the PT

	ms0 := new(big.Int).Mul(n1, n2)
	ms1 := new(big.Int).Mul(n0, n2)
	ms2 := new(big.Int).Mul(n0, n1)

	result0 := big.NewInt(0)
	result1 := big.NewInt(0)
	result2 := big.NewInt(0)
	invmod := new(big.Int)
	tmp := new(big.Int)

	invmod.ModInverse(ms0, n0)
	tmp.Mul(c0, ms0)
	tmp.Mul(tmp, invmod)
	result0.Add(result0, tmp)

	invmod.ModInverse(ms1, n1)
	tmp.Mul(c1, ms1)
	tmp.Mul(tmp, invmod)
	result1.Add(result1, tmp)

	invmod.ModInverse(ms2, n2)
	tmp.Mul(c2, ms2)
	tmp.Mul(tmp, invmod)
	result2.Add(result2, tmp)

	result := new(big.Int).Add(result0, result1)
	result.Add(result, result2)

	allN := new(big.Int).Mul(n0, n1)
	allN.Mul(allN, n2)

	result.Rem(result, allN)

	// result should now be that massive number
	// need to take the cube root of it
	return CubeRoot(result)
}
