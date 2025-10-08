// Package jwk provides JSON Web Key (JWK) support as defined in RFC 7517.
//
// JWK is a JSON data structure representing a cryptographic key. This package
// enables serialization and deserialization of keys in JWK format, supporting
// RSA, ECDSA, and Ed25519 keys.
package jwk

import (
	"encoding/json"
	"fmt"
)

// JWK represents a JSON Web Key as defined in RFC 7517.
//
// A JWK is a JSON object that represents a cryptographic key. Different key types
// use different parameter sets.
type JWK struct {
	// Common parameters (all key types)
	KeyType   string   `json:"kty"`                  // Key Type: "RSA", "EC", "OKP", "oct"
	Use       string   `json:"use,omitempty"`        // Public Key Use: "sig" (signature) or "enc" (encryption)
	KeyOps    []string `json:"key_ops,omitempty"`    // Key Operations
	Algorithm string   `json:"alg,omitempty"`        // Algorithm intended for use with the key
	KeyID     string   `json:"kid,omitempty"`        // Key ID

	// RSA parameters (RFC 7518 Section 6.3)
	N string `json:"n,omitempty"` // Modulus (Base64URL)
	E string `json:"e,omitempty"` // Exponent (Base64URL)
	D string `json:"d,omitempty"` // Private exponent (Base64URL) - for private keys only
	P string `json:"p,omitempty"` // First prime factor - for private keys only
	Q string `json:"q,omitempty"` // Second prime factor - for private keys only
	DP string `json:"dp,omitempty"` // First factor CRT exponent - for private keys only
	DQ string `json:"dq,omitempty"` // Second factor CRT exponent - for private keys only
	QI string `json:"qi,omitempty"` // First CRT coefficient - for private keys only

	// EC parameters (RFC 7518 Section 6.2)
	Curve string `json:"crv,omitempty"` // Curve: "P-256", "P-384", "P-521"
	X     string `json:"x,omitempty"`   // X coordinate (Base64URL)
	Y     string `json:"y,omitempty"`   // Y coordinate (Base64URL)

	// OKP (Octet Key Pair) parameters for Ed25519/X25519 (RFC 8037)
	// Uses Curve and X from above
	// Curve: "Ed25519" or "X25519"
	// X: Public key bytes

	// Symmetric key parameter (RFC 7518 Section 6.4)
	K string `json:"k,omitempty"` // Key value (Base64URL) - for symmetric keys
}

// Parse parses a JWK from JSON bytes.
//
// Parameters:
//   - data: JSON-encoded JWK
//
// Returns:
//   - *JWK: The parsed JWK
//   - error: Any parsing error
//
// Example:
//
//	jwkData := []byte(`{"kty":"RSA","n":"...","e":"AQAB"}`)
//	jwk, err := jwk.Parse(jwkData)
func Parse(data []byte) (*JWK, error) {
	var j JWK
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	// Validate required fields
	if j.KeyType == "" {
		return nil, fmt.Errorf("%w: kty (key type)", ErrMissingRequiredField)
	}

	// Validate key-type-specific required fields
	if err := j.validate(); err != nil {
		return nil, err
	}

	return &j, nil
}

// Marshal serializes the JWK to JSON bytes.
//
// Returns:
//   - []byte: JSON-encoded JWK
//   - error: Any marshaling error
//
// Example:
//
//	data, err := jwk.Marshal()
func (j *JWK) Marshal() ([]byte, error) {
	return json.Marshal(j)
}

// MarshalIndent serializes the JWK to indented JSON bytes for pretty printing.
//
// Parameters:
//   - prefix: String to prefix each line with
//   - indent: String to use for each indentation level
//
// Returns:
//   - []byte: Indented JSON-encoded JWK
//   - error: Any marshaling error
//
// Example:
//
//	data, err := jwk.MarshalIndent("", "  ")
func (j *JWK) MarshalIndent(prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(j, prefix, indent)
}

// validate checks that required fields for the key type are present.
func (j *JWK) validate() error {
	switch j.KeyType {
	case "RSA":
		if j.N == "" || j.E == "" {
			return fmt.Errorf("%w: RSA keys require 'n' and 'e'", ErrMissingRequiredField)
		}
	case "EC":
		if j.Curve == "" || j.X == "" || j.Y == "" {
			return fmt.Errorf("%w: EC keys require 'crv', 'x', and 'y'", ErrMissingRequiredField)
		}
	case "OKP":
		if j.Curve == "" || j.X == "" {
			return fmt.Errorf("%w: OKP keys require 'crv' and 'x'", ErrMissingRequiredField)
		}
	case "oct":
		if j.K == "" {
			return fmt.Errorf("%w: symmetric keys require 'k'", ErrMissingRequiredField)
		}
	default:
		return fmt.Errorf("%w: %s", ErrInvalidKeyType, j.KeyType)
	}

	return nil
}

// IsPrivate returns true if this JWK contains private key material.
//
// A JWK is considered private if it contains the private exponent (d) for RSA,
// or equivalent private key data for other key types.
//
// Returns:
//   - bool: true if private key material is present
//
// Example:
//
//	if jwk.IsPrivate() {
//	    // Handle private key securely
//	}
func (j *JWK) IsPrivate() bool {
	switch j.KeyType {
	case "RSA":
		return j.D != ""
	case "EC":
		return j.D != ""
	case "OKP":
		// For OKP, we don't currently support private keys in this implementation
		// as the plan focuses on public key JWKs
		return false
	case "oct":
		// Symmetric keys are always considered "private"
		return j.K != ""
	default:
		return false
	}
}
