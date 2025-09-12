package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"github.com/jasoet/gopki/keypair/algo"
)

// GenerateRSAKeyPair generates an RSA key pair with type safety
func GenerateRSAKeyPair[T *rsa.PrivateKey](keySize int) (T, error) {
	var zero T
	
	keyPair, err := algo.GenerateRSAKeyPair(keySize)
	if err != nil {
		return zero, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	
	return T(keyPair.PrivateKey), nil
}

// GenerateECDSAKeyPair generates an ECDSA key pair with type safety
func GenerateECDSAKeyPair[T *ecdsa.PrivateKey](curve algo.ECDSACurve) (T, error) {
	var zero T
	
	keyPair, err := algo.GenerateECDSAKeyPair(curve)
	if err != nil {
		return zero, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}
	
	return T(keyPair.PrivateKey), nil
}

// GenerateEd25519KeyPair generates an Ed25519 key pair with type safety
func GenerateEd25519KeyPair[T ed25519.PrivateKey]() (T, error) {
	var zero T
	
	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		return zero, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	
	return T(keyPair.PrivateKey), nil
}

// PrivateKeyToPEM converts any supported private key to PEM format with type safety
func PrivateKeyToPEM[T PrivateKey](privateKey T) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// PublicKeyToPEM converts any supported public key to PEM format with type safety
func PublicKeyToPEM[T PublicKey](publicKey T) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

// GetPublicKey extracts the public key from a private key with type safety
func GetPublicKey[TPriv PrivateKey, TPub PublicKey](privateKey TPriv) (TPub, error) {
	var zero TPub
	
	switch priv := any(privateKey).(type) {
	case *rsa.PrivateKey:
		if pub, ok := any(&priv.PublicKey).(TPub); ok {
			return pub, nil
		}
	case *ecdsa.PrivateKey:
		if pub, ok := any(&priv.PublicKey).(TPub); ok {
			return pub, nil
		}
	case ed25519.PrivateKey:
		if pub, ok := any(priv.Public().(ed25519.PublicKey)).(TPub); ok {
			return pub, nil
		}
	}
	
	return zero, fmt.Errorf("unsupported key type or type mismatch")
}

// Convenience functions that use generics but provide simpler API

// NewRSAKeyPair generates a new RSA key pair and returns the private key
func NewRSAKeyPair(keySize int) (*rsa.PrivateKey, error) {
	return GenerateRSAKeyPair[*rsa.PrivateKey](keySize)
}

// NewECDSAKeyPair generates a new ECDSA key pair and returns the private key
func NewECDSAKeyPair(curve algo.ECDSACurve) (*ecdsa.PrivateKey, error) {
	return GenerateECDSAKeyPair[*ecdsa.PrivateKey](curve)
}

// NewEd25519KeyPair generates a new Ed25519 key pair and returns the private key
func NewEd25519KeyPair() (ed25519.PrivateKey, error) {
	return GenerateEd25519KeyPair[ed25519.PrivateKey]()
}

// RSAPublicKeyFromPrivate extracts the RSA public key from private key
func RSAPublicKeyFromPrivate(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	return &privateKey.PublicKey
}

// ECDSAPublicKeyFromPrivate extracts the ECDSA public key from private key
func ECDSAPublicKeyFromPrivate(privateKey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return &privateKey.PublicKey
}

// Ed25519PublicKeyFromPrivate extracts the Ed25519 public key from private key
func Ed25519PublicKeyFromPrivate(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	return privateKey.Public().(ed25519.PublicKey)
}

// KeyPairToPEM converts a private key to both private and public PEM formats
func KeyPairToPEM[TPriv PrivateKey, TPub PublicKey](privateKey TPriv, publicKey TPub) (privatePEM, publicPEM []byte, err error) {
	privatePEM, err = PrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert private key to PEM: %w", err)
	}
	
	publicPEM, err = PublicKeyToPEM(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}
	
	return privatePEM, publicPEM, nil
}

// Algorithm detection helpers

// DetectAlgorithmFromPEM detects the algorithm type from PEM data
func DetectAlgorithmFromPEM(pemData []byte) (string, error) {
	// Try RSA first
	if _, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		return "RSA", nil
	}
	
	// Try ECDSA
	if _, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		return "ECDSA", nil
	}
	
	// Try Ed25519
	if _, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		return "Ed25519", nil
	}
	
	return "", fmt.Errorf("unable to detect algorithm: unsupported or invalid key format")
}

// ParseAnyPrivateKeyFromPEM attempts to parse a private key and returns algorithm info
func ParseAnyPrivateKeyFromPEM(pemData []byte) (privateKey interface{}, algorithm string, err error) {
	// Try RSA
	if rsaKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		return rsaKey, "RSA", nil
	}
	
	// Try ECDSA
	if ecdsaKey, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		return ecdsaKey, "ECDSA", nil
	}
	
	// Try Ed25519
	if ed25519Key, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		return ed25519Key, "Ed25519", nil
	}
	
	return nil, "", fmt.Errorf("unable to parse private key: unsupported algorithm or invalid format")
}

// SaveKeyPairToFiles saves both private and public keys to files
func SaveKeyPairToFiles[TPriv PrivateKey, TPub PublicKey](privateKey TPriv, publicKey TPub, privateFile, publicFile string) error {
	privatePEM, publicPEM, err := KeyPairToPEM(privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert keys to PEM: %w", err)
	}
	
	// Save private key
	if err := savePEMToFile(privatePEM, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	
	// Save public key
	if err := savePEMToFile(publicPEM, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	
	return nil
}

// Helper function for saving PEM to file
func savePEMToFile(pemData []byte, filename string) error {
	return os.WriteFile(filename, pemData, 0600)
}