package jwk

import (
	"encoding/json"
	"fmt"
)

// JWKSet represents a JSON Web Key Set as defined in RFC 7517.
//
// A JWK Set is a JSON object that contains an array of JWKs. This structure
// is commonly used for publishing public keys (e.g., OIDC .well-known/jwks.json).
type JWKSet struct {
	Keys []JWK `json:"keys"` // Array of JWK objects
}

// ParseSet parses a JWK Set from JSON bytes.
//
// Parameters:
//   - data: JSON-encoded JWK Set
//
// Returns:
//   - *JWKSet: The parsed JWK Set
//   - error: Any parsing error
//
// Example:
//
//	jwksData := []byte(`{"keys":[{"kty":"RSA","n":"...","e":"AQAB"}]}`)
//	jwks, err := jwk.ParseSet(jwksData)
func ParseSet(data []byte) (*JWKSet, error) {
	var set JWKSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("failed to parse JWK Set: %w", err)
	}

	// Validate each key in the set
	for i := range set.Keys {
		if err := set.Keys[i].validate(); err != nil {
			return nil, fmt.Errorf("invalid key at index %d: %w", i, err)
		}
	}

	return &set, nil
}

// Marshal serializes the JWK Set to JSON bytes.
//
// Returns:
//   - []byte: JSON-encoded JWK Set
//   - error: Any marshaling error
//
// Example:
//
//	data, err := jwks.Marshal()
func (s *JWKSet) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// MarshalIndent serializes the JWK Set to indented JSON bytes for pretty printing.
//
// Parameters:
//   - prefix: String to prefix each line with
//   - indent: String to use for each indentation level
//
// Returns:
//   - []byte: Indented JSON-encoded JWK Set
//   - error: Any marshaling error
//
// Example:
//
//	data, err := jwks.MarshalIndent("", "  ")
func (s *JWKSet) MarshalIndent(prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(s, prefix, indent)
}

// FindByKeyID finds a JWK in the set by its Key ID (kid).
//
// Parameters:
//   - kid: Key ID to search for
//
// Returns:
//   - *JWK: The matching JWK, or nil if not found
//   - error: ErrKeyNotFound if no matching key exists
//
// Example:
//
//	jwk, err := jwks.FindByKeyID("rsa-2024-01")
func (s *JWKSet) FindByKeyID(kid string) (*JWK, error) {
	for i := range s.Keys {
		if s.Keys[i].KeyID == kid {
			return &s.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
}

// FindByUse finds all JWKs in the set with the specified use.
//
// Parameters:
//   - use: Key use to filter by ("sig" or "enc")
//
// Returns:
//   - []JWK: Slice of matching JWKs (may be empty)
//
// Example:
//
//	sigKeys := jwks.FindByUse("sig")
func (s *JWKSet) FindByUse(use string) []JWK {
	var matches []JWK
	for i := range s.Keys {
		if s.Keys[i].Use == use {
			matches = append(matches, s.Keys[i])
		}
	}
	return matches
}

// Add adds a JWK to the set.
//
// Parameters:
//   - key: The JWK to add
//
// Example:
//
//	jwks.Add(jwk)
func (s *JWKSet) Add(key *JWK) {
	if key != nil {
		s.Keys = append(s.Keys, *key)
	}
}

// Remove removes a JWK from the set by its Key ID (kid).
//
// Parameters:
//   - kid: Key ID of the JWK to remove
//
// Returns:
//   - bool: true if a key was removed, false if not found
//
// Example:
//
//	removed := jwks.Remove("old-key-1")
func (s *JWKSet) Remove(kid string) bool {
	for i := range s.Keys {
		if s.Keys[i].KeyID == kid {
			// Remove by slicing
			s.Keys = append(s.Keys[:i], s.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// Len returns the number of keys in the set.
//
// Returns:
//   - int: Number of keys
//
// Example:
//
//	count := jwks.Len()
func (s *JWKSet) Len() int {
	return len(s.Keys)
}
