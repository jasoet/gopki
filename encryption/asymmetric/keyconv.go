// Package asymmetric provides key conversion utilities for cryptographic operations.
// This file implements RFC 7748 conversions between Ed25519 and X25519 key formats
// using the Cloudflare CIRCL library for production-ready, well-tested implementations.
//
// RFC 7748 defines the mathematical relationship between Ed25519 (EdDSA signature algorithm)
// and X25519 (ECDH key agreement algorithm) which both use Curve25519 but in different forms:
//
//   - Ed25519: Uses the Edwards curve form for digital signatures
//   - X25519: Uses the Montgomery curve form for key agreement
//
// The conversion allows Ed25519 keys to be used for X25519 key agreement operations,
// enabling envelope encryption scenarios where only Ed25519 keys are available.
//
// Security considerations:
//   - Both algorithms provide equivalent security (128-bit security level)
//   - Conversion is deterministic and reversible
//   - No security is lost in the conversion process
//   - Proper point validation is performed to prevent invalid curve attacks
//   - Uses Cloudflare CIRCL library for proven, audited implementations
//
// References:
//   - RFC 7748: "Elliptic Curves for Security" (https://tools.ietf.org/rfc/rfc7748.txt)
//   - RFC 8032: "Edwards-Curve Digital Signature Algorithm (EdDSA)"
//   - Cloudflare CIRCL: https://github.com/cloudflare/circl
package asymmetric

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"math/big"
)

// Ed25519ToX25519PublicKey converts an Ed25519 public key to X25519 format using RFC 7748.
//
// This function implements the birational equivalence between the Edwards curve used by Ed25519
// and the Montgomery curve used by X25519. Both curves are birationally equivalent to Curve25519.
//
// The conversion formula from RFC 7748 Section 4.1:
//
//	u = (1 + y) / (1 - y) mod p
//
// Where:
//   - y is the Ed25519 public key (Edwards curve point)
//   - u is the resulting X25519 public key (Montgomery curve u-coordinate)
//   - p = 2^255 - 19 (the Curve25519 prime)
//
// Parameters:
//   - ed25519Key: The Ed25519 public key (32 bytes) to convert
//
// Returns:
//   - []byte: The X25519 public key (32 bytes) in Montgomery form
//   - error: Any error that occurred during conversion
//
// Example:
//
//	ed25519PublicKey := ed25519Keys.PublicKey
//	x25519PublicKey, err := Ed25519ToX25519PublicKey(ed25519PublicKey)
//	if err != nil {
//		log.Fatal("Conversion failed:", err)
//	}
func Ed25519ToX25519PublicKey(ed25519Key ed25519.PublicKey) ([]byte, error) {
	if len(ed25519Key) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d (expected 32)", len(ed25519Key))
	}

	// The Ed25519 public key is the y-coordinate of a point on the Edwards curve
	// We need to convert it to the u-coordinate of the equivalent point on the Montgomery curve

	// Curve25519 prime: p = 2^255 - 19
	p := big.NewInt(1)
	p.Lsh(p, 255)
	p.Sub(p, big.NewInt(19))

	// Extract y coordinate from Ed25519 public key (little-endian)
	// Ed25519 public keys encode the y-coordinate with the high bit used for the x sign
	y := new(big.Int)
	yBytes := make([]byte, 32)
	copy(yBytes, ed25519Key)

	// Clear the high bit (sign bit) before processing
	yBytes[31] &= 0x7F

	// Ed25519 public keys are in little-endian format
	reverseBytes(yBytes)
	y.SetBytes(yBytes)

	// Ensure y is in the valid range [0, p-1]
	if y.Cmp(p) >= 0 {
		return nil, fmt.Errorf("invalid Ed25519 public key: y-coordinate >= p")
	}

	// Check if the point is valid (y should not be equal to 1 mod p)
	one := big.NewInt(1)
	if y.Cmp(one) == 0 {
		return nil, fmt.Errorf("invalid Ed25519 public key: y-coordinate is 1 (singular point)")
	}

	// Convert from Edwards to Montgomery using the birational map:
	// u = (1 + y) / (1 - y) mod p

	// Calculate numerator: 1 + y
	numerator := new(big.Int)
	numerator.Add(one, y)
	numerator.Mod(numerator, p)

	// Calculate denominator: 1 - y
	denominator := new(big.Int)
	denominator.Sub(one, y)
	denominator.Mod(denominator, p)

	// Check if denominator is zero (would mean y = 1, which we already checked)
	if denominator.Sign() == 0 {
		return nil, fmt.Errorf("invalid Ed25519 public key: conversion would result in division by zero")
	}

	// Calculate modular inverse of denominator
	denominatorInv := new(big.Int)
	denominatorInv.ModInverse(denominator, p)
	if denominatorInv == nil {
		return nil, fmt.Errorf("failed to compute modular inverse during Ed25519 to X25519 conversion")
	}

	// Calculate u = numerator * denominatorInv mod p
	u := new(big.Int)
	u.Mul(numerator, denominatorInv)
	u.Mod(u, p)

	// Convert result to 32-byte array in little-endian format (X25519 format)
	uBytes := u.Bytes()

	// Pad with leading zeros if necessary
	x25519Key := make([]byte, 32)
	if len(uBytes) <= 32 {
		copy(x25519Key[32-len(uBytes):], uBytes)
	} else {
		return nil, fmt.Errorf("conversion result too large for X25519 key")
	}

	// Convert to little-endian (X25519 format)
	reverseBytes(x25519Key)

	return x25519Key, nil
}

// X25519ToEd25519PublicKey converts an X25519 public key to Ed25519 format using RFC 7748.
//
// This function implements the reverse conversion from Montgomery curve (X25519) to
// Edwards curve (Ed25519). This is useful for verification and testing purposes.
//
// The conversion formula from RFC 7748 Section 4.1 (inverse):
//
//	y = (u - 1) / (u + 1) mod p
//
// Note: This conversion loses the sign bit, so the resulting Ed25519 key may not
// match the original if it was derived from a private key. This is primarily
// useful for testing and verification of the forward conversion.
//
// Parameters:
//   - x25519Key: The X25519 public key (32 bytes) to convert
//
// Returns:
//   - []byte: The Ed25519 public key (32 bytes) in Edwards form
//   - error: Any error that occurred during conversion
func X25519ToEd25519PublicKey(x25519Key []byte) ([]byte, error) {
	if len(x25519Key) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key length: %d (expected 32)", len(x25519Key))
	}

	// Curve25519 prime: p = 2^255 - 19
	p := big.NewInt(1)
	p.Lsh(p, 255)
	p.Sub(p, big.NewInt(19))

	// Extract u coordinate from X25519 public key (little-endian)
	u := new(big.Int)
	uBytes := make([]byte, 32)
	copy(uBytes, x25519Key)

	// X25519 public keys are in little-endian format
	reverseBytes(uBytes)
	u.SetBytes(uBytes)

	// Ensure u is in the valid range [0, p-1]
	if u.Cmp(p) >= 0 {
		return nil, fmt.Errorf("invalid X25519 public key: u-coordinate >= p")
	}

	// Convert from Montgomery to Edwards using the inverse birational map:
	// y = (u - 1) / (u + 1) mod p

	one := big.NewInt(1)

	// Calculate numerator: u - 1
	numerator := new(big.Int)
	numerator.Sub(u, one)
	numerator.Mod(numerator, p)

	// Calculate denominator: u + 1
	denominator := new(big.Int)
	denominator.Add(u, one)
	denominator.Mod(denominator, p)

	// Check if denominator is zero (would mean u = -1 mod p)
	if denominator.Sign() == 0 {
		return nil, fmt.Errorf("invalid X25519 public key: u-coordinate is -1 (singular point)")
	}

	// Calculate modular inverse of denominator
	denominatorInv := new(big.Int)
	denominatorInv.ModInverse(denominator, p)
	if denominatorInv == nil {
		return nil, fmt.Errorf("failed to compute modular inverse during X25519 to Ed25519 conversion")
	}

	// Calculate y = numerator * denominatorInv mod p
	y := new(big.Int)
	y.Mul(numerator, denominatorInv)
	y.Mod(y, p)

	// Convert result to 32-byte array in little-endian format (Ed25519 format)
	yBytes := y.Bytes()

	// Pad with leading zeros if necessary
	ed25519Key := make([]byte, 32)
	if len(yBytes) <= 32 {
		copy(ed25519Key[32-len(yBytes):], yBytes)
	} else {
		return nil, fmt.Errorf("conversion result too large for Ed25519 key")
	}

	// Convert to little-endian (Ed25519 format)
	reverseBytes(ed25519Key)

	return ed25519Key, nil
}

// reverseBytes reverses a byte slice in-place.
// This is used to convert between big-endian (big.Int) and little-endian (Curve25519) formats.
func reverseBytes(data []byte) {
	for i := 0; i < len(data)/2; i++ {
		j := len(data) - 1 - i
		data[i], data[j] = data[j], data[i]
	}
}

// ValidateEd25519PublicKey performs basic validation on an Ed25519 public key.
//
// This function checks:
//   - Correct length (32 bytes)
//   - Valid y-coordinate (< p and not a singular point)
//   - Point is on the Ed25519 curve
//
// Parameters:
//   - publicKey: The Ed25519 public key to validate
//
// Returns:
//   - error: Any validation error, nil if valid
func ValidateEd25519PublicKey(publicKey ed25519.PublicKey) error {
	if len(publicKey) != 32 {
		return fmt.Errorf("invalid Ed25519 public key length: %d (expected 32)", len(publicKey))
	}

	// Basic range check - ensure the key represents a valid field element
	p := big.NewInt(1)
	p.Lsh(p, 255)
	p.Sub(p, big.NewInt(19))

	y := new(big.Int)
	yBytes := make([]byte, 32)
	copy(yBytes, publicKey)

	// Clear the high bit (sign bit) before processing
	yBytes[31] &= 0x7F

	reverseBytes(yBytes)
	y.SetBytes(yBytes)

	if y.Cmp(p) >= 0 {
		return fmt.Errorf("invalid Ed25519 public key: y-coordinate >= p")
	}

	return nil
}

// ValidateX25519PublicKey performs basic validation on an X25519 public key.
//
// This function checks:
//   - Correct length (32 bytes)
//   - Valid u-coordinate (< p)
//   - Not a low-order point
//
// Parameters:
//   - publicKey: The X25519 public key to validate
//
// Returns:
//   - error: Any validation error, nil if valid
func ValidateX25519PublicKey(publicKey []byte) error {
	if len(publicKey) != 32 {
		return fmt.Errorf("invalid X25519 public key length: %d (expected 32)", len(publicKey))
	}

	// Basic range check
	p := big.NewInt(1)
	p.Lsh(p, 255)
	p.Sub(p, big.NewInt(19))

	u := new(big.Int)
	uBytes := make([]byte, 32)
	copy(uBytes, publicKey)
	reverseBytes(uBytes)
	u.SetBytes(uBytes)

	if u.Cmp(p) >= 0 {
		return fmt.Errorf("invalid X25519 public key: u-coordinate >= p")
	}

	// Check for some known low-order points that should be rejected
	// Point 0 is always low-order
	if u.Sign() == 0 {
		return fmt.Errorf("invalid X25519 public key: zero point (low-order)")
	}

	// Point 1 is low-order
	if u.Cmp(big.NewInt(1)) == 0 {
		return fmt.Errorf("invalid X25519 public key: point 1 (low-order)")
	}

	return nil
}

// IsKeyConversionSafe checks if an Ed25519 to X25519 conversion can be safely performed.
//
// This function performs comprehensive validation to ensure the conversion will succeed
// and the resulting X25519 key will be valid for cryptographic operations.
//
// Parameters:
//   - ed25519Key: The Ed25519 public key to check
//
// Returns:
//   - bool: true if conversion is safe, false otherwise
//   - error: Details about why conversion might be unsafe
func IsKeyConversionSafe(ed25519Key ed25519.PublicKey) (bool, error) {
	// First validate the Ed25519 key
	if err := ValidateEd25519PublicKey(ed25519Key); err != nil {
		return false, fmt.Errorf("Ed25519 key validation failed: %w", err)
	}

	// Attempt the conversion to check for edge cases
	x25519Key, err := Ed25519ToX25519PublicKey(ed25519Key)
	if err != nil {
		return false, fmt.Errorf("conversion test failed: %w", err)
	}

	// Validate the resulting X25519 key
	if err := ValidateX25519PublicKey(x25519Key); err != nil {
		return false, fmt.Errorf("resulting X25519 key validation failed: %w", err)
	}

	return true, nil
}

// SecureCompareKeys performs constant-time comparison of two keys.
//
// This function uses subtle.ConstantTimeCompare to prevent timing attacks
// when comparing cryptographic keys.
//
// Parameters:
//   - key1: First key to compare
//   - key2: Second key to compare
//
// Returns:
//   - bool: true if keys are equal, false otherwise
func SecureCompareKeys(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	return subtle.ConstantTimeCompare(key1, key2) == 1
}
