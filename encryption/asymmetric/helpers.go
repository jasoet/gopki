package asymmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// deriveAESKey derives an AES-256 key from a shared secret using HKDF.
//
// This function uses HKDF (HMAC-based Key Derivation Function) with SHA-256
// to derive a deterministic 256-bit AES key from the provided shared secret.
// The same shared secret will always produce the same AES key.
//
// Parameters:
//   - sharedSecret: The shared secret obtained from key agreement (ECDH/X25519)
//
// Returns:
//   - []byte: A 32-byte (256-bit) AES key derived from the shared secret
//
// Security properties:
//   - Uses HKDF with SHA-256 for cryptographically strong key derivation
//   - Includes a salt value ("GoPKI-AES-Key") for domain separation
//   - Produces uniformly distributed key material
func deriveAESKey(sharedSecret []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("GoPKI-AES-Key"))
	key := make([]byte, 32) // 256-bit key
	_, _ = io.ReadFull(hkdf, key)
	return key
}

// encryptAESGCM encrypts data using AES-256-GCM with a random nonce.
//
// AES-GCM provides authenticated encryption, ensuring both confidentiality
// and integrity of the encrypted data. A random nonce is generated for each
// encryption operation to ensure semantic security.
//
// Parameters:
//   - data: The plaintext data to encrypt
//   - key: The 32-byte AES-256 key
//
// Returns:
//   - []byte: The encrypted ciphertext
//   - []byte: The random nonce (IV) used for encryption
//   - []byte: The authentication tag for integrity verification
//   - error: Any error that occurred during encryption
//
// Security properties:
//   - AES-256-GCM authenticated encryption
//   - Random nonce for each encryption (semantic security)
//   - Authentication tag prevents tampering
func encryptAESGCM(data []byte, key []byte) ([]byte, []byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Separate the ciphertext and tag
	tagStart := len(ciphertext) - gcm.Overhead()
	actualCiphertext := ciphertext[:tagStart]
	tag := ciphertext[tagStart:]

	return actualCiphertext, nonce, tag, nil
}

// decryptAESGCM decrypts AES-256-GCM encrypted data with authentication verification.
//
// This function reverses the AES-GCM encryption process, verifying the authentication
// tag to ensure data integrity before returning the plaintext.
//
// Parameters:
//   - ciphertext: The encrypted data to decrypt
//   - key: The 32-byte AES-256 key used for encryption
//   - nonce: The nonce (IV) used during encryption
//   - tag: The authentication tag for integrity verification
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error that occurred during decryption or authentication failure
//
// Security properties:
//   - Authentication tag verification prevents tampering
//   - Constant-time comparison for tag verification
//   - Fails securely on authentication errors
func decryptAESGCM(ciphertext []byte, key []byte, nonce []byte, tag []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Reconstruct the full ciphertext with tag
	fullCiphertext := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}
