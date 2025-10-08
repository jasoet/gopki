package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/jasoet/gopki/jose/internal/encoding"
	"github.com/jasoet/gopki/keypair"
)

// ToPublicKey converts a JWK to a Go standard library public key.
//
// Supported key types:
//   - RSA → *rsa.PublicKey
//   - EC → *ecdsa.PublicKey
//   - OKP → ed25519.PublicKey
//
// Returns:
//   - keypair.GenericPublicKey: The public key
//   - error: Any conversion error
//
// Example:
//
//	jwk, _ := jwk.Parse(jwkJSON)
//	publicKey, err := jwk.ToPublicKey()
//	rsaKey := publicKey.(*rsa.PublicKey) // Type assertion
func (j *JWK) ToPublicKey() (keypair.GenericPublicKey, error) {
	switch j.KeyType {
	case "RSA":
		return j.toRSAPublicKey()
	case "EC":
		return j.toECDSAPublicKey()
	case "OKP":
		return j.toOKPPublicKey()
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidKeyType, j.KeyType)
	}
}

// toRSAPublicKey converts JWK to *rsa.PublicKey.
func (j *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := encoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := encoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Validate exponent fits in int
	if !e.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large")
	}

	eInt := int(e.Int64())
	if eInt <= 0 {
		return nil, fmt.Errorf("invalid RSA exponent: %d", eInt)
	}

	return &rsa.PublicKey{
		N: n,
		E: eInt,
	}, nil
}

// toECDSAPublicKey converts JWK to *ecdsa.PublicKey.
func (j *JWK) toECDSAPublicKey() (*ecdsa.PublicKey, error) {
	// Get curve
	curve, err := parseCurve(j.Curve)
	if err != nil {
		return nil, err
	}

	// Decode X coordinate
	xBytes, err := encoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC X coordinate: %w", err)
	}

	// Decode Y coordinate
	yBytes, err := encoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC Y coordinate: %w", err)
	}

	// Convert to big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Create public key
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Validate point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC point is not on curve %s", j.Curve)
	}

	return publicKey, nil
}

// toOKPPublicKey converts JWK to ed25519.PublicKey.
func (j *JWK) toOKPPublicKey() (ed25519.PublicKey, error) {
	// Currently only support Ed25519
	if j.Curve != "Ed25519" {
		return nil, fmt.Errorf("%w: %s (only Ed25519 supported)", ErrInvalidCurve, j.Curve)
	}

	// Decode X coordinate (public key bytes)
	xBytes, err := encoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 public key: %w", err)
	}

	// Validate size
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d (expected %d)", len(xBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(xBytes), nil
}

// parseCurve converts JWK curve name to elliptic.Curve.
func parseCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidCurve, name)
	}
}
