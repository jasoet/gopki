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
	"github.com/jasoet/gopki/keypair/format"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
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

// GenericPrivateKey represents any private key type for functions that need to work with multiple key types dynamically
type GenericPrivateKey any

// GenericPublicKey represents any public key type for functions that need to work with multiple key types dynamically
type GenericPublicKey any

// GenericKeyPair represents any keypair type for functions that need to work with multiple keypair types dynamically
type GenericKeyPair any

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
func PrivateKeyToPEM[T PrivateKey](privateKey T) (format.PEM, error) {
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
func PublicKeyToPEM[T PublicKey](publicKey T) (format.PEM, error) {
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

// PrivateKeyToDER converts a private key to DER-encoded format.
// The key is marshaled using PKCS#8 format for maximum compatibility.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//
// Returns DER-encoded data or an error if conversion fails.
//
// Example:
//
//	derData, err := PrivateKeyToDER(rsaPrivateKey)
//	if err != nil {
//		log.Printf("Failed to convert private key: %v", err)
//	}
func PrivateKeyToDER[T PrivateKey](privateKey T) (format.DER, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return privateKeyBytes, nil
}

// PublicKeyToDER converts a public key to DER-encoded format.
// The key is marshaled using PKIX format for standard compatibility.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//
// Returns DER-encoded data or an error if conversion fails.
//
// Example:
//
//	derData, err := PublicKeyToDER(rsaPublicKey)
//	if err != nil {
//		log.Printf("Failed to convert public key: %v", err)
//	}
func PublicKeyToDER[T PublicKey](publicKey T) (format.DER, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return publicKeyBytes, nil
}

// PrivateKeyToSSH converts a private key to SSH-encoded format.
// The key is marshaled using OpenSSH private key format with optional passphrase protection.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//   - comment: Optional comment to embed in the key file
//   - passphrase: Optional passphrase for key encryption (empty string for unencrypted)
//
// Returns SSH-encoded data or an error if conversion fails.
//
// Security note: Using a passphrase is recommended for private key storage.
//
// Example:
//
//	sshData, err := PrivateKeyToSSH(rsaPrivateKey, "my-key", "secure-passphrase")
//	if err != nil {
//		log.Printf("Failed to convert private key: %v", err)
//	}
func PrivateKeyToSSH[T PrivateKey](privateKey T, comment string, passphrase string) (format.SSH, error) {
	var pemBlock *pem.Block
	var err error

	if passphrase == "" {
		pemBlock, err = ssh.MarshalPrivateKey(privateKey, comment)
	} else {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, []byte(passphrase))
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal SSH private key: %w", err)
	}

	sshPrivateKey := pem.EncodeToMemory(pemBlock)
	return format.SSH(sshPrivateKey), nil
}

// PublicKeyToSSH converts a public key to SSH-encoded format.
// The key is marshaled using SSH public key format suitable for authorized_keys files.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//   - comment: Optional comment to include in the SSH key (commonly username@hostname)
//
// Returns SSH-encoded data in format "ssh-rsa base64-key [comment]" or an error if conversion fails.
//
// Example:
//
//	sshData, err := PublicKeyToSSH(rsaPublicKey, "user@example.com")
//	if err != nil {
//		log.Printf("Failed to convert public key: %v", err)
//	}
func PublicKeyToSSH[T PublicKey](publicKey T, comment string) (format.SSH, error) {
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert to SSH public key: %w", err)
	}

	sshData := ssh.MarshalAuthorizedKey(sshPubKey)
	sshStr := strings.TrimSpace(string(sshData))

	// Add comment if provided and not already present
	if comment != "" && !strings.Contains(sshStr, comment) {
		parts := strings.SplitN(sshStr, " ", 3)
		if len(parts) >= 2 {
			sshStr = parts[0] + " " + parts[1] + " " + comment
		}
	}

	return format.SSH(sshStr), nil
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
	var privateKeyPEM, publicKeyPEM format.PEM
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

// GetPrivateKeyFromKeyPair extracts the private key from a KeyPair with type safety.
// This function works with all supported KeyPair types and maintains type relationships.
//
// Type parameters:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - keyPair: The key pair from which to extract the private key
//
// Returns the corresponding private key or an error if extraction fails or type mismatch occurs.
//
// Examples:
//
//	// Extract RSA private key with explicit types
//	rsaPriv, err := GetPrivateKeyFromKeyPair[*algo.RSAKeyPair, *rsa.PrivateKey](rsaKeyPair)
//
//	// Extract ECDSA private key with type inference
//	ecdsaPriv, err := GetPrivateKeyFromKeyPair[*algo.ECDSAKeyPair, *ecdsa.PrivateKey](ecdsaKeyPair)
//
//	// Extract Ed25519 private key
//	ed25519Priv, err := GetPrivateKeyFromKeyPair[*algo.Ed25519KeyPair, ed25519.PrivateKey](ed25519KeyPair)
func GetPrivateKeyFromKeyPair[K KeyPair, T PrivateKey](keyPair K) (T, error) {
	var zero T

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		if priv, ok := any(kp.PrivateKey).(T); ok {
			return priv, nil
		}
	case *algo.ECDSAKeyPair:
		if priv, ok := any(kp.PrivateKey).(T); ok {
			return priv, nil
		}
	case *algo.Ed25519KeyPair:
		if priv, ok := any(kp.PrivateKey).(T); ok {
			return priv, nil
		}
	}

	return zero, fmt.Errorf("unsupported key pair type or type mismatch")
}

// GetPublicKeyFromKeyPair extracts the public key from a KeyPair with type safety.
// This function works with all supported KeyPair types and maintains type relationships.
//
// Type parameters:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - keyPair: The key pair from which to extract the public key
//
// Returns the corresponding public key or an error if extraction fails or type mismatch occurs.
//
// Examples:
//
//	// Extract RSA public key with explicit types
//	rsaPub, err := GetPublicKeyFromKeyPair[*algo.RSAKeyPair, *rsa.PublicKey](rsaKeyPair)
//
//	// Extract ECDSA public key with type inference
//	ecdsaPub, err := GetPublicKeyFromKeyPair[*algo.ECDSAKeyPair, *ecdsa.PublicKey](ecdsaKeyPair)
//
//	// Extract Ed25519 public key
//	ed25519Pub, err := GetPublicKeyFromKeyPair[*algo.Ed25519KeyPair, ed25519.PublicKey](ed25519KeyPair)
func GetPublicKeyFromKeyPair[K KeyPair, T PublicKey](keyPair K) (T, error) {
	var zero T

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		if pub, ok := any(kp.PublicKey).(T); ok {
			return pub, nil
		}
	case *algo.ECDSAKeyPair:
		if pub, ok := any(kp.PublicKey).(T); ok {
			return pub, nil
		}
	case *algo.Ed25519KeyPair:
		if pub, ok := any(kp.PublicKey).(T); ok {
			return pub, nil
		}
	}

	return zero, fmt.Errorf("unsupported key pair type or type mismatch")
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
func savePEMToFile(pemData format.PEM, filename string) error {
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
