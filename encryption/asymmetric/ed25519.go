package asymmetric

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

// EncryptWithEd25519 encrypts data using X25519 key agreement + AES-GCM.
//
// Note: Ed25519 keys cannot be directly used for ECDH. This function uses a workaround
// by deriving an X25519 key from the Ed25519 private key seed for key agreement.
//
// This provides a bridge between Ed25519 signing keys and X25519 encryption keys,
// allowing the same key material to be used for both signing and encryption operations
// (though this is generally not recommended for security reasons).
//
// Process:
//  1. Extract seed from Ed25519 private key
//  2. Derive X25519 private key from the seed
//  3. Generate ephemeral X25519 key pair for forward secrecy
//  4. Perform X25519 key agreement to get shared secret
//  5. Derive AES-256 key from shared secret
//  6. Encrypt data with AES-GCM using derived key
//
// Parameters:
//   - data: The plaintext data to encrypt (no size limitations)
//   - keyPair: The Ed25519 key pair (converted to X25519 for encryption)
//   - opts: Encryption options (algorithm will be set to AlgorithmX25519)
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data with X25519 algorithm metadata
//   - error: Any error that occurred during key derivation, agreement, or encryption
//
// Security considerations:
//   - Using Ed25519 keys for encryption is not standard practice
//   - Perfect forward secrecy through ephemeral X25519 keys
//   - Authenticated encryption via AES-GCM
//
// Example:
//
//	ed25519Keys, _ := algo.GenerateEd25519KeyPair()
//	data := []byte("data to encrypt")
//
//	encrypted, err := asymmetric.EncryptWithEd25519(data, ed25519Keys, opts)
//	if err != nil {
//		log.Fatal("Ed25519 encryption failed:", err)
//	}
func EncryptWithEd25519(data []byte, keyPair *algo.Ed25519KeyPair, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if err := encryption.ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Ed25519 keys can't be directly converted to X25519 for ECDH
	// We need to use the private key seed to derive an X25519 key
	curve := ecdh.X25519()

	// Use the Ed25519 private key seed to derive X25519 private key
	seed := keyPair.PrivateKey.Seed()
	x25519PrivateKey, err := curve.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key from Ed25519 seed: %w", err)
	}

	// Get the corresponding X25519 public key
	x25519PublicKey := x25519PrivateKey.PublicKey()

	// Generate ephemeral key pair for forward secrecy
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}

	// Perform X25519 key agreement between ephemeral key and derived X25519 public key
	sharedSecret, err := ephemeralPrivateKey.ECDH(x25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := deriveAESKey(sharedSecret)

	// Encrypt data using AES-GCM
	encryptedData, iv, tag, err := encryptAESGCM(data, aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	return &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmX25519,
		Format:       opts.Format,
		Data:         encryptedData,
		EncryptedKey: ephemeralPrivateKey.PublicKey().Bytes(), // Store ephemeral public key
		IV:           iv,
		Tag:          tag,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// DecryptWithEd25519 decrypts X25519 + AES-GCM encrypted data.
//
// This function reverses the Ed25519 encryption process by:
//  1. Extracting seed from Ed25519 private key
//  2. Deriving the same X25519 private key used for encryption
//  3. Extracting sender's ephemeral X25519 public key from encrypted data
//  4. Performing X25519 key agreement to recover shared secret
//  5. Deriving the same AES key used for encryption
//  6. Decrypting data using AES-GCM
//
// Parameters:
//   - encrypted: The encrypted data to decrypt (must contain ephemeral key)
//   - keyPair: The Ed25519 key pair (converted to X25519 for decryption)
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error that occurred during key derivation, agreement, or decryption
//
// Example:
//
//	plaintext, err := asymmetric.DecryptWithEd25519(encrypted, ed25519Keys, opts)
func DecryptWithEd25519(encrypted *encryption.EncryptedData, keyPair *algo.Ed25519KeyPair, opts encryption.DecryptOptions) ([]byte, error) {
	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != encryption.AlgorithmX25519 {
		return nil, fmt.Errorf("expected X25519 algorithm, got %s", encrypted.Algorithm)
	}

	// Derive X25519 private key from Ed25519 private key seed
	// This must match the derivation used during encryption
	curve := ecdh.X25519()
	seed := keyPair.PrivateKey.Seed()
	x25519PrivateKey, err := curve.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key from Ed25519 seed: %w", err)
	}

	// Parse ephemeral public key from encrypted data
	ephemeralPublicKey, err := curve.NewPublicKey(encrypted.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Perform X25519 key agreement between our derived private key and ephemeral public key
	sharedSecret, err := x25519PrivateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive AES key from shared secret (same derivation as encryption)
	aesKey := deriveAESKey(sharedSecret)

	// Decrypt data using AES-GCM
	decrypted, err := decryptAESGCM(encrypted.Data, aesKey, encrypted.IV, encrypted.Tag)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return decrypted, nil
}
