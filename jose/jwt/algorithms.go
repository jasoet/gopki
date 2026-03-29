package jwt

import (
	"crypto"
	"fmt"
)

// Algorithm represents JWT signing algorithm as defined in RFC 7518
type Algorithm string

const (
	// RS256 is the RSA PKCS#1 v1.5 + SHA-256 algorithm.
	RS256 Algorithm = "RS256"
	// RS384 is the RSA PKCS#1 v1.5 + SHA-384 algorithm.
	RS384 Algorithm = "RS384"
	// RS512 is the RSA PKCS#1 v1.5 + SHA-512 algorithm.
	RS512 Algorithm = "RS512"

	// PS256 is the RSA-PSS + SHA-256 algorithm.
	PS256 Algorithm = "PS256"
	// PS384 is the RSA-PSS + SHA-384 algorithm.
	PS384 Algorithm = "PS384"
	// PS512 is the RSA-PSS + SHA-512 algorithm.
	PS512 Algorithm = "PS512"

	// ES256 is the ECDSA P-256 + SHA-256 algorithm.
	ES256 Algorithm = "ES256"
	// ES384 is the ECDSA P-384 + SHA-384 algorithm.
	ES384 Algorithm = "ES384"
	// ES512 is the ECDSA P-521 + SHA-512 algorithm.
	ES512 Algorithm = "ES512"

	// EdDSA is the Ed25519 algorithm (RFC 8032).
	EdDSA Algorithm = "EdDSA"

	// HS256 is the HMAC + SHA-256 algorithm (symmetric).
	HS256 Algorithm = "HS256"
	// HS384 is the HMAC + SHA-384 algorithm (symmetric).
	HS384 Algorithm = "HS384"
	// HS512 is the HMAC + SHA-512 algorithm (symmetric).
	HS512 Algorithm = "HS512"
)

// HashFunc returns the hash function for the algorithm
func (a Algorithm) HashFunc() (crypto.Hash, error) {
	switch a {
	case RS256, PS256, ES256, HS256:
		return crypto.SHA256, nil
	case RS384, PS384, ES384, HS384:
		return crypto.SHA384, nil
	case RS512, PS512, ES512, HS512:
		return crypto.SHA512, nil
	case EdDSA:
		return 0, nil // Ed25519 doesn't use a separate hash
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, a)
	}
}

// IsHMAC returns true if algorithm is HMAC-based (symmetric)
func (a Algorithm) IsHMAC() bool {
	return a == HS256 || a == HS384 || a == HS512
}

// IsRSA returns true if algorithm is RSA-based
func (a Algorithm) IsRSA() bool {
	return a == RS256 || a == RS384 || a == RS512 ||
		a == PS256 || a == PS384 || a == PS512
}

// IsECDSA returns true if algorithm is ECDSA-based
func (a Algorithm) IsECDSA() bool {
	return a == ES256 || a == ES384 || a == ES512
}

// IsEdDSA returns true if algorithm is Ed25519
func (a Algorithm) IsEdDSA() bool {
	return a == EdDSA
}

// Validate validates the algorithm and rejects insecure algorithms
func (a Algorithm) Validate() error {
	// Explicitly reject 'none' algorithm (security)
	if string(a) == "none" || string(a) == "" {
		return ErrAlgorithmNone
	}

	// Validate against supported algorithms
	validAlgorithms := map[Algorithm]bool{
		RS256: true, RS384: true, RS512: true,
		PS256: true, PS384: true, PS512: true,
		ES256: true, ES384: true, ES512: true,
		EdDSA: true,
		HS256: true, HS384: true, HS512: true,
	}

	if !validAlgorithms[a] {
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, a)
	}

	return nil
}
