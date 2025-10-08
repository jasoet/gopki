package jwt

import (
	"fmt"
	"strings"
)

const (
	// MaxTokenSize is the maximum allowed token size (8KB)
	MaxTokenSize = 8192
)

// Token represents a parsed JWT token
type Token struct {
	// Header contains JWT header (alg, typ, kid)
	Header Header

	// Claims contains the JWT claims
	Claims *Claims

	// Raw components (Base64URL encoded)
	RawHeader    string
	RawClaims    string
	RawSignature string

	// Signature bytes (decoded)
	Signature []byte
}

// Header represents the JWT header (JOSE header)
type Header struct {
	Algorithm Algorithm `json:"alg"`           // Signing algorithm (required)
	Type      string    `json:"typ,omitempty"` // Token type (usually "JWT")
	KeyID     string    `json:"kid,omitempty"` // Key ID for key rotation
}

// String returns the compact JWT representation (header.payload.signature)
func (t *Token) String() string {
	return t.RawHeader + "." + t.RawClaims + "." + t.RawSignature
}

// SigningInput returns the data to be signed (header.claims)
func (t *Token) SigningInput() string {
	return t.RawHeader + "." + t.RawClaims
}

// Parse parses a JWT string without verification
// This only validates the structure and decoding, not the signature
func Parse(tokenString string) (*Token, error) {
	// Check token size to prevent DoS
	if len(tokenString) > MaxTokenSize {
		return nil, ErrTokenTooLarge
	}

	// Split into header.payload.signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidTokenFormat
	}

	// Decode and unmarshal header
	var header Header
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	// Validate algorithm (reject 'none', validate supported)
	if err := header.Algorithm.Validate(); err != nil {
		return nil, err
	}

	// Decode and unmarshal claims
	var claims Claims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Decode signature
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	return &Token{
		Header:       header,
		Claims:       &claims,
		RawHeader:    parts[0],
		RawClaims:    parts[1],
		RawSignature: parts[2],
		Signature:    signature,
	}, nil
}
