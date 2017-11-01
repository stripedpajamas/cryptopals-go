package challenge28

func SHA1MAC(key, message []byte) [20]byte {
	input := append(key, message...)
	return Sum(input)
}