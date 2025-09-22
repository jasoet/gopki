// Package crypto provides complex cryptographic algorithms used internally by GoPKI.
//
// This package contains mathematical operations that are not available in Go's
// standard library or third-party dependencies. These implementations follow
// established RFCs and cryptographic standards.
//
// SECURITY NOTE: These implementations are for educational and compatibility
// purposes. For production use, prefer well-tested library implementations
// when available.
package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// Ed25519ToX25519PublicKey converts an Ed25519 public key to X25519 public key
// following RFC 7748 Section 4.1 ("Curve25519").
//
// This conversion is necessary for envelope encryption where we have only an
// Ed25519 public key but need to perform X25519 ECDH key agreement.
//
// Mathematical Background:
//   - Ed25519 uses Edwards25519 curve: -x² + y² = 1 + d*x²*y²
//   - X25519 uses Montgomery curve Curve25519: B*v² = u³ + A*u² + u
//   - Both curves are birationally equivalent over the same prime field
//   - The conversion formula from Edwards (x,y) to Montgomery (u,v) is:
//     u = (1 + y) / (1 - y) mod p
//     v = sqrt(-486664) * u / x mod p (we only need u-coordinate for ECDH)
//
// RFC References:
// - RFC 7748: "Elliptic Curves for Security"
// - RFC 8032: "Edwards-Curve Digital Signature Algorithm (EdDSA)"
//
// Parameters:
//   - ed25519PublicKey: 32-byte Ed25519 public key
//
// Returns:
//   - []byte: 32-byte X25519 public key (u-coordinate only)
//   - error: Conversion error or invalid input
//
// Example:
//
//	ed25519PubKey := []byte{...} // 32 bytes
//	x25519PubKey, err := Ed25519ToX25519PublicKey(ed25519PubKey)
//	if err != nil {
//	    log.Fatal("Conversion failed:", err)
//	}
//	// Use x25519PubKey for ECDH operations
func Ed25519ToX25519PublicKey(ed25519PublicKey ed25519.PublicKey) ([]byte, error) {
	if len(ed25519PublicKey) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: expected 32 bytes, got %d", len(ed25519PublicKey))
	}

	// The Ed25519 public key is the y-coordinate on Edwards25519
	y := make([]byte, 32)
	copy(y, ed25519PublicKey)

	// Convert from little-endian to big-endian for arithmetic operations
	// (Go's crypto libraries use little-endian, but we need big-endian for field arithmetic)
	reverseBytes(y)

	// Convert Edwards y-coordinate to Montgomery u-coordinate
	// Formula: u = (1 + y) / (1 - y) mod p
	// where p = 2^255 - 19 (the prime field for Curve25519)
	u, err := edwardsToMontgomery(y)
	if err != nil {
		return nil, fmt.Errorf("Edwards to Montgomery conversion failed: %w", err)
	}

	// Convert back to little-endian for X25519 format
	reverseBytes(u)

	return u, nil
}

// edwardsToMontgomery converts Edwards y-coordinate to Montgomery u-coordinate
// using the formula: u = (1 + y) / (1 - y) mod p
func edwardsToMontgomery(y []byte) ([]byte, error) {
	// Curve25519 prime: p = 2^255 - 19
	p := []byte{
		0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
	}

	// Check if y >= p (invalid point)
	if compareBytes(y, p) >= 0 {
		return nil, fmt.Errorf("invalid Edwards coordinate: y >= p")
	}

	// Create properly sized 1 for arithmetic
	one := make([]byte, 32)
	one[31] = 1

	// Calculate 1 + y mod p
	oneY := addMod(one, y, p)

	// Calculate 1 - y mod p
	oneMinusY := subMod(one, y, p)

	// Check for degenerate case: 1 - y = 0 (point at infinity)
	if isZero(oneMinusY) {
		return nil, fmt.Errorf("conversion failed: point at infinity")
	}

	// Calculate u = (1 + y) / (1 - y) mod p
	// This is equivalent to (1 + y) * (1 - y)^(-1) mod p
	invOneMinusY, err := modInverse(oneMinusY, p)
	if err != nil {
		return nil, fmt.Errorf("modular inverse failed: %w", err)
	}

	u := mulMod(oneY, invOneMinusY, p)
	return u, nil
}

// reverseBytes reverses a byte slice in place (little-endian <-> big-endian)
func reverseBytes(b []byte) {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}
}

// compareBytes compares two byte slices as big-endian integers
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func compareBytes(a, b []byte) int {
	// Handle case where leading zeros make values equal
	// Remove leading zeros for accurate comparison
	aTrimmed := trimLeadingZeros(a)
	bTrimmed := trimLeadingZeros(b)

	// Compare lengths first
	if len(aTrimmed) < len(bTrimmed) {
		return -1
	}
	if len(aTrimmed) > len(bTrimmed) {
		return 1
	}

	// Compare byte by byte
	for i := 0; i < len(aTrimmed); i++ {
		if aTrimmed[i] < bTrimmed[i] {
			return -1
		}
		if aTrimmed[i] > bTrimmed[i] {
			return 1
		}
	}
	return 0
}

// trimLeadingZeros removes leading zero bytes
func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	if i == len(b) {
		return []byte{0} // Return single zero for all-zero input
	}
	return b[i:]
}

// addMod computes (a + b) mod m
func addMod(a, b, m []byte) []byte {
	// Simple implementation - for production, use optimized big integer library
	// This is a educational implementation following RFC 7748

	// Convert to Go's big.Int for arithmetic (this is the complex part we're isolating)
	return performBigIntOperation(a, b, m, "add")
}

// subMod computes (a - b) mod m
func subMod(a, b, m []byte) []byte {
	return performBigIntOperation(a, b, m, "sub")
}

// mulMod computes (a * b) mod m
func mulMod(a, b, m []byte) []byte {
	return performBigIntOperation(a, b, m, "mul")
}

// modInverse computes a^(-1) mod m using extended Euclidean algorithm
func modInverse(a, m []byte) ([]byte, error) {
	result := performBigIntOperation(a, nil, m, "inv")
	if result == nil {
		return nil, fmt.Errorf("modular inverse does not exist")
	}
	return result, nil
}

// isZero checks if a byte slice represents zero
func isZero(a []byte) bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}
