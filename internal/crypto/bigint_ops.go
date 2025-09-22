// Package crypto - Big Integer Operations
//
// This file contains the complex mathematical operations using Go's big.Int
// library for arbitrary precision arithmetic required for elliptic curve
// point conversion between Ed25519 and X25519.
//
// These operations implement field arithmetic over the prime field p = 2^255 - 19
// used by Curve25519, as specified in RFC 7748.

package crypto

import (
	"math/big"
)

// performBigIntOperation performs various big integer operations
// This centralizes all the complex mathematical operations in one place
func performBigIntOperation(a, b, m []byte, operation string) []byte {
	// Convert byte arrays to big.Int
	aBig := new(big.Int).SetBytes(a)
	mBig := new(big.Int).SetBytes(m)

	var result *big.Int

	switch operation {
	case "add":
		bBig := new(big.Int).SetBytes(b)
		result = new(big.Int).Add(aBig, bBig)
		result.Mod(result, mBig)

	case "sub":
		bBig := new(big.Int).SetBytes(b)
		result = new(big.Int).Sub(aBig, bBig)
		// Handle negative results: if result < 0, add modulus
		if result.Sign() < 0 {
			result.Add(result, mBig)
		}
		result.Mod(result, mBig)

	case "mul":
		bBig := new(big.Int).SetBytes(b)
		result = new(big.Int).Mul(aBig, bBig)
		result.Mod(result, mBig)

	case "inv":
		// Modular inverse using extended Euclidean algorithm
		result = new(big.Int).ModInverse(aBig, mBig)
		if result == nil {
			return nil // Inverse doesn't exist
		}

	default:
		return nil
	}

	// Convert back to 32-byte array
	resultBytes := result.Bytes()

	// Pad to 32 bytes (big-endian)
	padded := make([]byte, 32)
	copy(padded[32-len(resultBytes):], resultBytes)

	return padded
}
