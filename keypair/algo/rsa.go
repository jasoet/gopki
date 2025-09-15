// Package algo provides algorithm-specific implementations for cryptographic key pair generation.
// This file contains RSA key pair generation and management functionality with security best practices.
package algo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeySize represents the bit size for RSA key generation.
// Valid values are 2048 or higher for security compliance.
type KeySize int

// RSAKeyPair represents a generated RSA key pair containing both private and public keys.
// The public key is derived from the private key to ensure mathematical relationship.
type RSAKeyPair struct {
	PrivateKey *rsa.PrivateKey // The RSA private key
	PublicKey  *rsa.PublicKey  // The corresponding RSA public key
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified key size.
// The function enforces a minimum key size of 2048 bits for security compliance.
//
// Parameters:
//   - keySize: The desired key size in bits (minimum 2048)
//
// Returns:
//   - *RSAKeyPair: The generated key pair
//   - error: Error if key size is too small or generation fails
//
// Security considerations:
//   - Uses crypto/rand.Reader for secure random number generation
//   - Enforces minimum 2048-bit key size as per current security standards
//   - Keys below 2048 bits are considered cryptographically weak
//
// Example:
//
//	keyPair, err := GenerateRSAKeyPair(2048)
//	if err != nil {
//		log.Printf("RSA key generation failed: %v", err)
//	}
func GenerateRSAKeyPair(keySize KeySize) (*RSAKeyPair, error) {
	if keySize < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, int(keySize))
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	return &RSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PrivateKeyToPEM converts the RSA private key to PEM format using PKCS#8 encoding.
// PKCS#8 format provides better interoperability compared to PKCS#1.
//
// Returns:
//   - []byte: PEM-encoded private key data
//   - error: Error if marshaling or encoding fails
//
// The returned PEM block will have type "PRIVATE KEY" and contain the
// PKCS#8 encoded private key data.
//
// Example:
//
//	pemData, err := keyPair.PrivateKeyToPEM()
//	if err != nil {
//		log.Printf("Private key PEM conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PrivateKeyToPEM() ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// PublicKeyToPEM converts the RSA public key to PEM format using PKIX encoding.
// PKIX format is the standard format for public key encoding in X.509 certificates.
//
// Returns:
//   - []byte: PEM-encoded public key data
//   - error: Error if marshaling or encoding fails
//
// The returned PEM block will have type "PUBLIC KEY" and contain the
// PKIX encoded public key data.
//
// Example:
//
//	pemData, err := keyPair.PublicKeyToPEM()
//	if err != nil {
//		log.Printf("Public key PEM conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PublicKeyToPEM() ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

// RSAKeyPairFromPEM reconstructs an RSA key pair from PEM-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyPEM: PEM-encoded private key data in PKCS#8 format
//
// Returns:
//   - *RSAKeyPair: The reconstructed key pair
//   - error: Error if PEM decoding, parsing, or type assertion fails
//
// The function expects the PEM block to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an RSA key before returning.
//
// Example:
//
//	keyPair, err := RSAKeyPairFromPEM(pemData)
//	if err != nil {
//		log.Printf("Failed to reconstruct RSA key pair: %v", err)
//	}
func RSAKeyPairFromPEM(privateKeyPEM []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return &RSAKeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  &rsaPrivateKey.PublicKey,
	}, nil
}
