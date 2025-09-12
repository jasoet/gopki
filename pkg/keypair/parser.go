package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PublicKey defines the supported public key types for generic parsing
type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// PrivateKey defines the supported private key types for generic parsing
type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// ParsePublicKeyFromPEM parses a public key from PEM format with type safety using Go generics.
// It returns the key as the specified type T or an error if parsing fails or the type is incorrect.
func ParsePublicKeyFromPEM[T PublicKey](pemData []byte) (T, error) {
	var zero T
	
	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return zero, fmt.Errorf("PEM block is not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse public key: %w", err)
	}

	typedKey, ok := publicKey.(T)
	if !ok {
		return zero, fmt.Errorf("public key is not of expected type")
	}

	return typedKey, nil
}

// ParsePrivateKeyFromPEM parses a private key from PEM format with type safety using Go generics.
// It returns the key as the specified type T or an error if parsing fails or the type is incorrect.
func ParsePrivateKeyFromPEM[T PrivateKey](pemData []byte) (T, error) {
	var zero T
	
	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return zero, fmt.Errorf("PEM block is not a private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse private key: %w", err)
	}

	typedKey, ok := privateKey.(T)
	if !ok {
		return zero, fmt.Errorf("private key is not of expected type")
	}

	return typedKey, nil
}

// ValidatePEMFormat validates that the provided data is in valid PEM format
// and contains either a public key or private key.
func ValidatePEMFormat(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "PRIVATE KEY" {
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return nil
}