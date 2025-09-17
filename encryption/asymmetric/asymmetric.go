// Package asymmetric provides asymmetric encryption operations using RSA, ECDSA, and Ed25519 algorithms.
//
// This package implements direct asymmetric encryption where data is encrypted directly
// using the recipient's public key. Due to the nature of asymmetric algorithms, there are
// practical size limitations for the data that can be encrypted:
//
//   - RSA: Limited to key size minus padding overhead (e.g., ~190 bytes for 2048-bit RSA)
//   - ECDSA: Uses ephemeral ECDH key agreement + AES-GCM for larger data support
//   - Ed25519: Uses X25519 key agreement + AES-GCM for larger data support
//
// For encrypting large amounts of data, consider using the envelope encryption package
// which combines the benefits of symmetric and asymmetric encryption.
//
// Security considerations:
//   - RSA-OAEP with SHA-256 for RSA operations
//   - ECDH key agreement with ephemeral keys for ECDSA
//   - X25519 key agreement with ephemeral keys for Ed25519
//   - AES-256-GCM for symmetric encryption in key agreement scenarios
//   - Cryptographically secure random number generation
//
// Example usage:
//
//	// RSA encryption
//	rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
//	encrypted, err := asymmetric.Encrypt(data, rsaKeys, opts)
//
//	// ECDSA encryption
//	ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	encrypted, err := asymmetric.Encrypt(data, ecdsaKeys, opts)
//
//	// Ed25519 encryption
//	ed25519Keys, _ := algo.GenerateEd25519KeyPair()
//	encrypted, err := asymmetric.Encrypt(data, ed25519Keys, opts)
package asymmetric

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// Encrypt encrypts data using asymmetric encryption with automatic algorithm selection
// based on the key pair type. This is the main entry point for asymmetric encryption.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - data: The plaintext data to encrypt
//   - keyPair: The key pair (public key used for encryption)
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: The encrypted data
//   - error: Any error that occurred during encryption
//
// Example:
//
//	rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
//	opts := encryption.EncryptOptions{
//		Algorithm: encryption.AlgorithmRSAOAEP,
//		Format:    encryption.FormatCMS,
//	}
//	encrypted, err := asymmetric.Encrypt(data, rsaKeys, opts)
func Encrypt[T keypair.KeyPair](data []byte, keyPair T, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		return EncryptWithRSA(data, kp, opts)
	case *algo.ECDSAKeyPair:
		return EncryptWithECDSA(data, kp, opts)
	case *algo.Ed25519KeyPair:
		return EncryptWithEd25519(data, kp, opts)
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// Decrypt decrypts asymmetrically encrypted data with automatic algorithm selection
// based on the key pair type.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - encrypted: The encrypted data to decrypt
//   - keyPair: The key pair (private key used for decryption)
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error that occurred during decryption
//
// Example:
//
//	plaintext, err := asymmetric.Decrypt(encrypted, rsaKeys, opts)
func Decrypt[T keypair.KeyPair](encrypted *encryption.EncryptedData, keyPair T, opts encryption.DecryptOptions) ([]byte, error) {
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		return DecryptWithRSA(encrypted, kp, opts)
	case *algo.ECDSAKeyPair:
		return DecryptWithECDSA(encrypted, kp, opts)
	case *algo.Ed25519KeyPair:
		return DecryptWithEd25519(encrypted, kp, opts)
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// EncryptForPublicKey encrypts data for a specific public key using the appropriate
// asymmetric algorithm. This is useful when you only have the public key available.
//
// Type parameter:
//   - T: Public key type constrained to keypair.PublicKey interface
//
// Parameters:
//   - data: The plaintext data to encrypt
//   - publicKey: The recipient's public key
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: The encrypted data
//   - error: Any error that occurred during encryption
//
// Example:
//
//	publicKey := rsaKeys.PublicKey()
//	encrypted, err := asymmetric.EncryptForPublicKey(data, publicKey, opts)
func EncryptForPublicKey[T keypair.PublicKey](data []byte, publicKey T, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	switch pk := any(publicKey).(type) {
	case *rsa.PublicKey:
		// For RSA, we can encrypt directly with the public key
		maxDataSize := pk.Size() - 2*sha256.Size - 2
		if len(data) > maxDataSize {
			return nil, fmt.Errorf("%w: data size %d exceeds maximum %d for RSA key size %d",
				encryption.ErrDataTooLarge, len(data), maxDataSize, pk.Size()*8)
		}

		encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, data, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
		}

		return &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmRSAOAEP,
			Format:    opts.Format,
			Data:      encrypted,
			Timestamp: time.Now(),
			Metadata:  opts.Metadata,
		}, nil

	case *ecdsa.PublicKey, ed25519.PublicKey:
		// For ECDSA and Ed25519, we need to generate ephemeral keys
		// This is more complex, so for now return an error
		// TODO: Implement ephemeral key generation and key agreement
		return nil, fmt.Errorf("EncryptForPublicKey not yet implemented for %T - use Encrypt with key pair instead", publicKey)

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// DecryptWithPrivateKey decrypts data using a private key.
// This is not typically used for asymmetric encryption - use Decrypt with key pair instead.
//
// Type parameter:
//   - T: Private key type constrained to keypair.PrivateKey interface
//
// Returns an error as this operation is not supported for asymmetric encryption.
func DecryptWithPrivateKey[T keypair.PrivateKey](encrypted *encryption.EncryptedData, privateKey T, opts encryption.DecryptOptions) ([]byte, error) {
	return nil, fmt.Errorf("DecryptWithPrivateKey not supported for asymmetric encryption - use Decrypt with key pair instead")
}

// SupportedAlgorithms returns the encryption algorithms supported by this package.
func SupportedAlgorithms() []encryption.EncryptionAlgorithm {
	return []encryption.EncryptionAlgorithm{
		encryption.AlgorithmRSAOAEP,
		encryption.AlgorithmECDH,
		encryption.AlgorithmX25519,
	}
}

// EncryptForPublicKeyAny is a non-generic wrapper for EncryptForPublicKey that works with any public key type.
// This is used internally by the envelope package for dynamic dispatch.
func EncryptForPublicKeyAny(data []byte, publicKey keypair.GenericPublicKey, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		return EncryptForPublicKey(data, pk, opts)
	case *ecdsa.PublicKey:
		return EncryptForPublicKey(data, pk, opts)
	case ed25519.PublicKey:
		return EncryptForPublicKey(data, pk, opts)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}