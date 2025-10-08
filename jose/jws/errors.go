package jws

import "errors"

// JWS-specific errors following GoPKI security best practices.
var (
	// ErrInvalidFormat indicates the JWS format is invalid
	ErrInvalidFormat = errors.New("invalid JWS format")

	// ErrNoValidSignature indicates no valid signature was found
	ErrNoValidSignature = errors.New("no valid signature found")

	// ErrInvalidDetachedFormat indicates detached JWS format is invalid
	ErrInvalidDetachedFormat = errors.New("invalid detached JWS format")

	// ErrNoSignatures indicates no signatures present in JSON serialization
	ErrNoSignatures = errors.New("no signatures present")

	// ErrInvalidJSON indicates JSON serialization is invalid
	ErrInvalidJSON = errors.New("invalid JWS JSON serialization")
)
