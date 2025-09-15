// Package keypair provides type-safe cryptographic key pair generation and management
// using Go generics for compile-time type safety. It supports RSA, ECDSA, and Ed25519
// algorithms with unified interfaces and format conversion utilities.
//
// The package uses generic constraints to ensure type safety at compile time:
//   - Param interface constrains key generation parameters
//   - KeyPair interface constrains key pair types
//   - PublicKey and PrivateKey interfaces constrain key types
//
// Example usage:
//
//	// Generate RSA key pair
//	rsaKeys, err := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//
//	// Generate ECDSA key pair
//	ecdsaKeys, err := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
//
//	// Generate Ed25519 key pair
//	ed25519Keys, err := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jasoet/gopki/keypair/algo"
	"os"
	"path/filepath"
)

// Param defines the constraint for key generation parameters.
// It accepts KeySize for RSA, ECDSACurve for ECDSA, or Ed25519Config for Ed25519.
type Param interface {
	algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair defines the constraint for key pair types.
// It accepts pointers to RSAKeyPair, ECDSAKeyPair, or Ed25519KeyPair.
type KeyPair interface {
	*algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// PublicKey defines the constraint for public key types.
// It accepts pointers to RSA/ECDSA public keys or Ed25519 public key values.
type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// PrivateKey defines the constraint for private key types.
// It accepts pointers to RSA/ECDSA private keys or Ed25519 private key values.
type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// PEM represents PEM-encoded key data as a byte slice.
// PEM format uses Base64 encoding with headers for text-based key storage.
type PEM []byte

// ValidatePEMFormat validates that the provided data is in proper PEM format
// and contains a supported key type (PUBLIC KEY or PRIVATE KEY).
//
// It returns an error if:
//   - The data is not valid PEM format
//   - The PEM block type is not PUBLIC KEY or PRIVATE KEY
//
// Example:
//
//	err := ValidatePEMFormat(pemData)
//	if err != nil {
//		log.Printf("Invalid PEM format: %v", err)
//	}
func ValidatePEMFormat(pemData PEM) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "PRIVATE KEY" {
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return nil
}

// GenerateKeyPair generates a cryptographic key pair using type-safe generic constraints.
// The function supports RSA, ECDSA, and Ed25519 algorithms with compile-time type safety.
//
// Type parameters:
//   - T: Parameter type (algo.KeySize, algo.ECDSACurve, or algo.Ed25519Config)
//   - K: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - param: Algorithm-specific parameter (key size, curve, or config)
//
// Returns the generated key pair or an error if generation fails.
//
// Examples:
//
//	// RSA key pair with 2048-bit key size
//	rsaKeys, err := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//
//	// ECDSA key pair with P-256 curve
//	ecdsaKeys, err := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
//
//	// Ed25519 key pair
//	ed25519Keys, err := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
func GenerateKeyPair[T Param, K KeyPair](param T) (K, error) {
	var zero K
	switch par := any(param).(type) {
	case algo.KeySize:
		kp, err := algo.GenerateRSAKeyPair(par)
		if err != nil {
			return zero, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
		return any(kp).(K), nil
	case algo.ECDSACurve:
		kp, err := algo.GenerateECDSAKeyPair(par)
		if err != nil {
			return zero, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}
		return any(kp).(K), nil
	case algo.Ed25519Config:
		kp, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			return zero, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
		}
		return any(kp).(K), nil
	default:
		return zero, fmt.Errorf("unsupported parameter type")
	}
}

// ParsePublicKeyFromPEM parses a public key from PEM-encoded data with type safety.
// The function uses generics to ensure the returned key matches the expected type.
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - pemData: PEM-encoded public key data
//
// Returns the parsed public key or an error if parsing fails or type doesn't match.
//
// Example:
//
//	rsaPublicKey, err := ParsePublicKeyFromPEM[*rsa.PublicKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse RSA public key: %v", err)
//	}
func ParsePublicKeyFromPEM[T PublicKey](pemData PEM) (T, error) {
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
func ParsePrivateKeyFromPEM[T PrivateKey](pemData PEM) (T, error) {
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

// PrivateKeyToPEM converts a private key to PEM-encoded format.
// The key is marshaled using PKCS#8 format for maximum compatibility.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//
// Returns PEM-encoded data or an error if conversion fails.
//
// Example:
//
//	pemData, err := PrivateKeyToPEM(rsaPrivateKey)
//	if err != nil {
//		log.Printf("Failed to convert private key: %v", err)
//	}
func PrivateKeyToPEM[T PrivateKey](privateKey T) (PEM, error) {
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

// PublicKeyToPEM converts a public key to PEM-encoded format.
// The key is marshaled using PKIX format for standard compatibility.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//
// Returns PEM-encoded data or an error if conversion fails.
//
// Example:
//
//	pemData, err := PublicKeyToPEM(rsaPublicKey)
//	if err != nil {
//		log.Printf("Failed to convert public key: %v", err)
//	}
func PublicKeyToPEM[T PublicKey](publicKey T) (PEM, error) {
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

// GetPublicKey extracts the public key from a private key with type safety.
// This function works with all supported key types and maintains type relationships.
//
// Type parameters:
//   - TPriv: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//   - TPub: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - privateKey: The private key from which to extract the public key
//
// Returns the corresponding public key or an error if extraction fails.
//
// Example:
//
//	rsaPublicKey, err := GetPublicKey[*rsa.PrivateKey, *rsa.PublicKey](rsaPrivateKey)
//	if err != nil {
//		log.Printf("Failed to get public key: %v", err)
//	}
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


// ToFiles saves a key pair to separate private and public key files in PEM format.
// The function creates the necessary directory structure and sets appropriate file permissions.
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - keyPair: The key pair to save
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency, though public keys could be more permissive)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := ToFiles(rsaKeyPair, "private.pem", "public.pem")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func ToFiles[T KeyPair](keyPair T, privateFile, publicFile string) error {
	var privateKeyPEM, publicKeyPEM PEM
	var err error

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA public key to PEM: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA public key to PEM: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(kp.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 public key to PEM: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	if err := savePEMToFile(privateKeyPEM, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := savePEMToFile(publicKeyPEM, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// savePEMToFile saves PEM-encoded data to a file with secure permissions.
// This is an internal helper function that handles directory creation and file permissions.
//
// Parameters:
//   - pemData: PEM-encoded data to save
//   - filename: Target file path
//
// The function:
//   - Creates parent directories with 0700 permissions
//   - Checks write permissions for existing files
//   - Saves files with 0600 permissions (owner read/write only)
//
// Returns an error if file operations fail.
func savePEMToFile(pemData PEM, filename string) error {
	dir := filepath.Dir(filename)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if _, err := os.Stat(filename); err == nil {
		file, err := os.OpenFile(filename, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("no write permission for existing file %s: %w", filename, err)
		}
		file.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check file status %s: %w", filename, err)
	}

	if err := os.WriteFile(filename, pemData, 0600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}
