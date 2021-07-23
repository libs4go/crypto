package keccak256

import "golang.org/x/crypto/sha3"

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, b := range data {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}
