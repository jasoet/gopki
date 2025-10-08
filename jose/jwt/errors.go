package jwt

import "errors"

// JWT-specific errors following GoPKI security best practices.
// Error messages are generic to prevent information leakage.
var (
	// ErrInvalidTokenFormat indicates the token format is invalid
	ErrInvalidTokenFormat = errors.New("invalid JWT format")

	// ErrInvalidSignature indicates signature verification failed
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenNotYetValid indicates the token is not yet valid (nbf)
	ErrTokenNotYetValid = errors.New("token not yet valid")

	// ErrInvalidIssuer indicates the issuer does not match expected value
	ErrInvalidIssuer = errors.New("invalid issuer")

	// ErrInvalidAudience indicates the audience does not match expected value
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrAlgorithmMismatch indicates algorithm in header doesn't match expected
	ErrAlgorithmMismatch = errors.New("algorithm mismatch")

	// ErrAlgorithmNone indicates 'none' algorithm was used (security risk)
	ErrAlgorithmNone = errors.New("'none' algorithm not allowed")

	// ErrTokenTooLarge indicates token exceeds maximum size limit
	ErrTokenTooLarge = errors.New("token too large")

	// ErrUnsupportedAlgorithm indicates algorithm is not supported
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	// ErrInvalidKey indicates the key type is invalid for the algorithm
	ErrInvalidKey = errors.New("invalid key type")
)
