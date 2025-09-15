package format

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/jasoet/gopki/keypair"
)

// ParsePrivateKeyFromPEM parses a private key from PEM-encoded data with type safety.
// The function uses generics to ensure the returned key matches the expected type.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - pemData: PEM-encoded private key data in PKCS#8 format
//
// Returns the parsed private key or an error if parsing fails or type doesn't match.
//
// Example:
//
//	rsaPrivateKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse RSA private key: %v", err)
//	}
func ParsePrivateKeyFromPEM[T keypair.PrivateKey](pemData keypair.PEM) (T, error) {
	var zero T

	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, NewFormatError(FormatPEM, "failed to decode PEM block", nil)
	}

	if block.Type != "PRIVATE KEY" {
		return zero, NewFormatError(FormatPEM, "PEM block is not a private key", nil)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return zero, NewFormatError(FormatPEM, "failed to parse private key", err)
	}

	typedKey, ok := privateKey.(T)
	if !ok {
		return zero, NewFormatError(FormatPEM, "private key is not of expected type", nil)
	}

	return typedKey, nil
}

// PrivateKeyFromPEM attempts to parse a private key from PEM data, auto-detecting the algorithm.
// This function tries all supported algorithms (RSA, ECDSA, Ed25519) and returns the first match.
// It's a convenience function that provides algorithm detection without requiring the caller
// to know the key type in advance.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - pemData: PEM-encoded private key data
//
// Returns:
//   - The parsed private key of the specified type
//   - Algorithm name ("RSA", "ECDSA", or "Ed25519")
//   - Error if parsing fails for all algorithms or type doesn't match
//
// The function attempts to parse the key with each supported algorithm until one succeeds.
// It then performs type assertion to ensure the result matches the expected type parameter.
//
// Example:
//
//	privateKey, algorithm, err := PrivateKeyFromPEM[*rsa.PrivateKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse private key: %v", err)
//	} else {
//		log.Printf("Parsed %s private key", algorithm)
//	}
func PrivateKeyFromPEM[T keypair.PrivateKey](pemData keypair.PEM) (T, string, error) {
	var zero T

	if rsaKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		if typedKey, ok := any(rsaKey).(T); ok {
			return typedKey, "RSA", nil
		}
	}

	if ecdsaKey, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		if typedKey, ok := any(ecdsaKey).(T); ok {
			return typedKey, "ECDSA", nil
		}
	}

	if ed25519Key, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		if typedKey, ok := any(ed25519Key).(T); ok {
			return typedKey, "Ed25519", nil
		}
	}

	return zero, "", NewFormatError(FormatPEM, "unable to parse private key: unsupported algorithm or invalid format", nil)
}