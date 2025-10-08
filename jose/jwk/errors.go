package jwk

import "errors"

var (
	// ErrInvalidKeyType indicates an unsupported or invalid key type
	ErrInvalidKeyType = errors.New("invalid or unsupported key type")

	// ErrInvalidJWK indicates the JWK format is invalid
	ErrInvalidJWK = errors.New("invalid JWK format")

	// ErrKeyNotFound indicates a key was not found in the set
	ErrKeyNotFound = errors.New("key not found")

	// ErrMissingRequiredField indicates a required JWK field is missing
	ErrMissingRequiredField = errors.New("missing required JWK field")

	// ErrInvalidCurve indicates an unsupported elliptic curve
	ErrInvalidCurve = errors.New("invalid or unsupported elliptic curve")
)
