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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

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

	case *ecdsa.PublicKey:
		// For ECDSA, use ephemeral ECDH key agreement + AES-GCM
		return encryptForECDSAPublicKey(data, pk, opts)

	case ed25519.PublicKey:
		// For Ed25519, use ephemeral X25519 key agreement + AES-GCM
		return encryptForEd25519PublicKey(data, pk, opts)

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// DecryptWithPrivateKey decrypts data using a private key.
// This function supports RSA-OAEP, ECDH, and X25519 algorithms by dispatching
// to the appropriate decryption method based on the private key type and algorithm.
//
// Type parameter:
//   - T: Private key type constrained to keypair.PrivateKey interface
//
// Parameters:
//   - encrypted: The encrypted data to decrypt
//   - privateKey: The private key to use for decryption
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error that occurred during decryption
func DecryptWithPrivateKey[T keypair.PrivateKey](encrypted *encryption.EncryptedData, privateKey T, opts encryption.DecryptOptions) ([]byte, error) {
	switch pk := any(privateKey).(type) {
	case *rsa.PrivateKey:
		// For RSA, decrypt directly using OAEP
		if encrypted.Algorithm != encryption.AlgorithmRSAOAEP {
			return nil, fmt.Errorf("expected RSA-OAEP algorithm for RSA private key, got %s", encrypted.Algorithm)
		}

		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pk, encrypted.Data, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
		}
		return plaintext, nil

	case *ecdsa.PrivateKey:
		// For ECDSA, use ECDH key agreement
		return decryptWithECDSAPrivateKey(encrypted, pk, opts)

	case ed25519.PrivateKey:
		// For Ed25519, use X25519 key agreement
		return decryptWithEd25519PrivateKey(encrypted, pk, opts)

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}

// SupportedAlgorithms returns the encryption algorithms supported by this package.
func SupportedAlgorithms() []encryption.Algorithm {
	return []encryption.Algorithm{
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

// Ephemeral Key Generation Utilities

// generateEphemeralECDSAKey generates an ephemeral ECDSA key pair for the same curve as the recipient's key.
// This is used for ECDH key agreement in envelope encryption scenarios.
func generateEphemeralECDSAKey(recipientKey *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	if recipientKey == nil {
		return nil, fmt.Errorf("recipient key cannot be nil")
	}

	ephemeralKey, err := ecdsa.GenerateKey(recipientKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral ECDSA key: %w", err)
	}

	return ephemeralKey, nil
}

// generateEphemeralX25519Key generates an ephemeral X25519 key pair for key agreement.
// This is used for Ed25519-based envelope encryption.
func generateEphemeralX25519Key() (*ecdh.PrivateKey, error) {
	x25519 := ecdh.X25519()
	ephemeralKey, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}

	return ephemeralKey, nil
}

// Key Agreement Functions

// performECDHKeyAgreement performs ECDH key agreement between private and public ECDSA keys.
// Returns the shared secret that can be used for key derivation.
func performECDHKeyAgreement(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	if privateKey == nil || publicKey == nil {
		return nil, fmt.Errorf("private key and public key cannot be nil")
	}

	if privateKey.Curve != publicKey.Curve {
		return nil, fmt.Errorf("curve mismatch: private key uses %s, public key uses %s",
			privateKey.Curve.Params().Name, publicKey.Curve.Params().Name)
	}

	// Perform ECDH key agreement
	x, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("ECDH key agreement failed: invalid result")
	}

	sharedSecret := x.Bytes()
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("ECDH key agreement failed: empty shared secret")
	}

	return sharedSecret, nil
}

// performX25519KeyAgreement performs X25519 key agreement.
// Returns the shared secret for key derivation.
func performX25519KeyAgreement(privateKey *ecdh.PrivateKey, publicKeyBytes []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key length: %d (expected 32)", len(publicKeyBytes))
	}

	// Convert bytes to X25519 public key
	x25519 := ecdh.X25519()
	publicKey, err := x25519.NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 public key: %w", err)
	}

	// Perform X25519 key agreement
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("X25519 key agreement failed: empty shared secret")
	}

	return sharedSecret, nil
}

// Key Derivation Functions

// deriveAESKeyFromSharedSecret derives an AES-256 key from a shared secret using HKDF-SHA256.
// The info parameter provides application-specific context for the key derivation.
func deriveAESKeyFromSharedSecret(sharedSecret []byte, info []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret cannot be empty")
	}

	// Use HKDF-SHA256 to derive a 32-byte AES key
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32) // AES-256 key size

	_, err := io.ReadFull(hkdfReader, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	return aesKey, nil
}

// Key Conversion Functions

// ed25519ToX25519PublicKey converts an Ed25519 public key to X25519 format for key agreement.
// This uses the standard conversion defined in RFC 7748.
//
// Note: This function is now a wrapper around the more comprehensive
// Ed25519ToX25519PublicKey function in keyconv.go for backward compatibility.
func ed25519ToX25519PublicKey(ed25519Key ed25519.PublicKey) ([]byte, error) {
	return Ed25519ToX25519PublicKey(ed25519Key)
}

// encryptForECDSAPublicKey encrypts data for an ECDSA public key using ephemeral ECDH key agreement.
// This function mirrors the logic from EncryptWithECDSA but works with just the public key.
func encryptForECDSAPublicKey(data []byte, publicKey *ecdsa.PublicKey, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	// Convert ECDSA public key to ECDH format
	ecdhPublicKey, err := publicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA public key to ECDH: %w", err)
	}

	// Generate ephemeral key pair for sender
	curve := ecdhPublicKey.Curve()
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH key agreement
	sharedSecret, err := ephemeralPrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// Derive AES key from shared secret using helper function
	aesKey := deriveAESKey(sharedSecret)

	// Encrypt data using AES-GCM
	encryptedData, iv, tag, err := encryptAESGCM(data, aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	// Include ephemeral public key for recipient
	ephemeralPublicKeyBytes := ephemeralPrivateKey.PublicKey().Bytes()

	return &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmECDH,
		Format:       opts.Format,
		Data:         encryptedData,
		EncryptedKey: ephemeralPublicKeyBytes, // Store ephemeral public key
		IV:           iv,
		Tag:          tag,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// encryptForEd25519PublicKey encrypts data for an Ed25519 public key using ephemeral X25519 key agreement.
// This function mirrors the logic from EncryptWithEd25519 but works with just the public key.
//
// NOTE: This function currently has a limitation - we can only encrypt for Ed25519 public keys
// if we also have access to the corresponding private key seed, because the Ed25519 public key
// to X25519 conversion is not compatible with Go's standard Ed25519 private key to X25519 conversion.
//
// For now, we return an error directing users to use the full key pair encryption method.
func encryptForEd25519PublicKey(data []byte, publicKey ed25519.PublicKey, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	return nil, fmt.Errorf("Ed25519 public-key-only encryption not yet supported due to key derivation incompatibility - use EncryptWithEd25519 with full key pair instead")
}

// decryptWithECDSAPrivateKey decrypts ECDH encrypted data using an ECDSA private key.
// This function mirrors the logic from DecryptWithECDSA but works with just the private key.
func decryptWithECDSAPrivateKey(encrypted *encryption.EncryptedData, privateKey *ecdsa.PrivateKey, opts encryption.DecryptOptions) ([]byte, error) {
	if encrypted.Algorithm != encryption.AlgorithmECDH {
		return nil, fmt.Errorf("expected ECDH algorithm for ECDSA private key, got %s", encrypted.Algorithm)
	}

	// Convert ECDSA private key to ECDH
	ecdhPrivateKey, err := privateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA private key to ECDH: %w", err)
	}

	// Parse ephemeral public key from ECDH bytes
	curve := ecdhPrivateKey.Curve()
	ephemeralECDHKey, err := curve.NewPublicKey(encrypted.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Perform ECDH key agreement
	sharedSecret, err := ecdhPrivateKey.ECDH(ephemeralECDHKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// Derive AES key from shared secret using helper function
	aesKey := deriveAESKey(sharedSecret)

	// Decrypt data using AES-GCM
	plaintext, err := decryptAESGCM(encrypted.Data, aesKey, encrypted.IV, encrypted.Tag)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// decryptWithEd25519PrivateKey decrypts X25519 encrypted data using an Ed25519 private key.
// This function mirrors the logic from DecryptWithEd25519 but works with just the private key.
func decryptWithEd25519PrivateKey(encrypted *encryption.EncryptedData, privateKey ed25519.PrivateKey, opts encryption.DecryptOptions) ([]byte, error) {
	if encrypted.Algorithm != encryption.AlgorithmX25519 {
		return nil, fmt.Errorf("expected X25519 algorithm for Ed25519 private key, got %s", encrypted.Algorithm)
	}

	// Convert Ed25519 private key to X25519 format
	curve := ecdh.X25519()
	seed := privateKey.Seed()
	x25519PrivateKey, err := curve.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key from Ed25519 seed: %w", err)
	}

	// Parse ephemeral public key from encrypted data
	ephemeralX25519Key, err := curve.NewPublicKey(encrypted.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral X25519 public key: %w", err)
	}

	// Perform X25519 key agreement
	sharedSecret, err := x25519PrivateKey.ECDH(ephemeralX25519Key)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive AES key from shared secret using helper function
	aesKey := deriveAESKey(sharedSecret)

	// Decrypt data using AES-GCM
	plaintext, err := decryptAESGCM(encrypted.Data, aesKey, encrypted.IV, encrypted.Tag)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}
