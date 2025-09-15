package algo

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Ed25519Config represents the configuration for Ed25519 key generation.
// Ed25519 has no configurable parameters, so this is used as a placeholder for generic constraints.
type Ed25519Config string

// Ed25519KeyPair represents a generated Ed25519 key pair containing both private and public keys.
// Ed25519 keys are fixed-length and offer high security with excellent performance.
type Ed25519KeyPair struct {
	PrivateKey ed25519.PrivateKey // The Ed25519 private key (64 bytes)
	PublicKey  ed25519.PublicKey  // The corresponding Ed25519 public key (32 bytes)
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
// Ed25519 is a modern elliptic curve signature algorithm that provides:
//   - High security (equivalent to ~3072-bit RSA)
//   - Fast key generation, signing, and verification
//   - Small key sizes (32-byte public keys, 64-byte private keys)
//   - Immunity to timing attacks
//
// Returns:
//   - *Ed25519KeyPair: The generated key pair
//   - error: Error if key generation fails
//
// Security considerations:
//   - Uses crypto/rand.Reader for secure random number generation
//   - No configurable parameters - the algorithm is designed to be secure by default
//   - Recommended for new applications requiring digital signatures
//
// Example:
//
//	keyPair, err := GenerateEd25519KeyPair()
//	if err != nil {
//		log.Printf("Ed25519 key generation failed: %v", err)
//	}
func GenerateEd25519KeyPair() (*Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	return &Ed25519KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// PrivateKeyToPEM converts the Ed25519 private key to PEM format using PKCS#8 encoding.
// PKCS#8 format ensures compatibility with standard cryptographic tools and libraries.
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
func (kp *Ed25519KeyPair) PrivateKeyToPEM() ([]byte, error) {
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

// PublicKeyToPEM converts the Ed25519 public key to PEM format using PKIX encoding.
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
func (kp *Ed25519KeyPair) PublicKeyToPEM() ([]byte, error) {
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

// Ed25519KeyPairFromPEM reconstructs an Ed25519 key pair from PEM-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyPEM: PEM-encoded private key data in PKCS#8 format
//
// Returns:
//   - *Ed25519KeyPair: The reconstructed key pair
//   - error: Error if PEM decoding, parsing, or type assertion fails
//
// The function expects the PEM block to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an Ed25519 key before returning.
// The public key is derived directly from the private key.
//
// Example:
//
//	keyPair, err := Ed25519KeyPairFromPEM(pemData)
//	if err != nil {
//		log.Printf("Failed to reconstruct Ed25519 key pair: %v", err)
//	}
func Ed25519KeyPairFromPEM(privateKeyPEM []byte) (*Ed25519KeyPair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an Ed25519 key")
	}

	publicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	return &Ed25519KeyPair{
		PrivateKey: ed25519PrivateKey,
		PublicKey:  publicKey,
	}, nil
}
