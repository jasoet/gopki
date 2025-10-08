package jwe

import "errors"

var (
	// ErrInvalidJWEFormat indicates the JWE format is invalid
	ErrInvalidJWEFormat = errors.New("invalid JWE format")

	// ErrInvalidJSON indicates the JWE JSON format is invalid
	ErrInvalidJSON = errors.New("invalid JWE JSON format")

	// ErrNoRecipients indicates no recipients were provided
	ErrNoRecipients = errors.New("no recipients provided")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	// ErrDecryptionFailed indicates decryption failed for all recipients
	ErrDecryptionFailed = errors.New("decryption failed for all recipients")
)
