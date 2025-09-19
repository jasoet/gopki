// Package symmetric provides AES-GCM symmetric encryption operations.
//
// This package implements authenticated encryption using AES-GCM (Galois/Counter Mode),
// which provides both confidentiality and authenticity in a single operation.
// AES-GCM is the recommended authenticated encryption mode for new applications.
//
// Features:
//   - AES-GCM authenticated encryption with 128, 192, or 256-bit keys
//   - HKDF (HMAC-based Key Derivation Function) for key derivation
//   - Automatic nonce generation for each encryption operation
//   - Authentication tag verification during decryption
//   - Password-based key derivation with PBKDF2
//
// Security properties:
//   - Confidentiality: Data is encrypted with AES in counter mode
//   - Authenticity: GMAC provides authentication of both data and AAD
//   - Integrity: Any tampering with ciphertext is detected during decryption
//   - Nonce misuse resistance: Each encryption uses a unique random nonce
//
// Performance characteristics:
//   - High performance on modern processors with AES-NI instructions
//   - Parallelizable encryption and decryption
//   - Minimal overhead compared to AES-CTR + HMAC
//
// Example usage:
//
//	// Generate a random key
//	key, err := symmetric.GenerateAESKey(32)  // 256-bit key
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Encrypt data
//	opts := encryption.EncryptOptions{
//		Algorithm: encryption.AlgorithmAESGCM,
//		Format:    encryption.FormatCMS,
//	}
//	encrypted, err := symmetric.EncryptAESGCM(data, key, opts)
//
//	// Decrypt data
//	decrypted, err := symmetric.DecryptAESGCM(encrypted, key, opts)
package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/jasoet/gopki/encryption"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptAESGCM encrypts data using AES-GCM authenticated encryption with the provided key.
//
// This function implements authenticated encryption using AES in Galois/Counter Mode.
// It automatically generates a unique nonce for each encryption operation and
// includes the authentication tag in the output for integrity verification.
//
// Key requirements:
//   - Must be exactly 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
//   - Should be cryptographically random or derived using a secure KDF
//   - Must not be reused across different encryption contexts
//
// Parameters:
//   - data: The plaintext data to encrypt (no size limitations)
//   - key: The AES encryption key (16, 24, or 32 bytes)
//   - opts: Encryption options (algorithm will be set to AlgorithmAESGCM)
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data containing nonce + ciphertext + auth tag
//   - error: Invalid key size or encryption failure
//
// Security properties:
//   - Semantic security: identical plaintexts produce different ciphertexts
//   - Authentication: tampering with ciphertext is detected during decryption
//   - Nonce uniqueness: each encryption uses a fresh 96-bit random nonce
//
// Performance:
//   - Efficient on hardware with AES-NI instructions
//   - Suitable for encrypting data of any size
//   - Lower overhead than separate encryption + MAC operations
//
// Example:
//
//	key := make([]byte, 32)  // 256-bit key
//	_, _ = rand.Read(key)
//	encrypted, err := symmetric.EncryptAESGCM(data, key, opts)
//	if err != nil {
//		log.Fatal("AES-GCM encryption failed:", err)
//	}
func EncryptAESGCM(data []byte, key []byte, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if err := encryption.ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Validate key size
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key size: %d bytes (must be 16, 24, or 32)", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Extract authentication tag (last 16 bytes)
	tagStart := len(ciphertext) - gcm.Overhead()
	actualCiphertext := ciphertext[:tagStart]
	tag := ciphertext[tagStart:]

	return &encryption.EncryptedData{
		Algorithm: encryption.AlgorithmAESGCM,
		Format:    opts.Format,
		Data:      actualCiphertext,
		IV:        nonce,
		Tag:       tag,
		Timestamp: time.Now(),
		Metadata:  opts.Metadata,
	}, nil
}

// DecryptAESGCM decrypts AES-GCM encrypted data with authentication verification.
//
// This function reverses the AES-GCM encryption process, verifying the authentication
// tag to ensure data integrity before returning the plaintext. If the authentication
// tag verification fails, the function returns an error and no plaintext is revealed.
//
// Parameters:
//   - encrypted: The encrypted data structure containing ciphertext, nonce, and tag
//   - key: The same AES key used for encryption (16, 24, or 32 bytes)
//   - opts: Decryption options for validation
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Authentication failure, invalid parameters, or decryption error
//
// Security guarantees:
//   - Authentication: Returns error if data has been tampered with
//   - Constant-time tag verification: Prevents timing attacks
//   - No partial decryption: Either succeeds completely or fails entirely
//
// Example:
//
//	decrypted, err := symmetric.DecryptAESGCM(encrypted, key, opts)
//	if err != nil {
//		log.Fatal("AES-GCM decryption failed:", err)
//	}
func DecryptAESGCM(encrypted *encryption.EncryptedData, key []byte, opts encryption.DecryptOptions) ([]byte, error) {
	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != encryption.AlgorithmAESGCM {
		return nil, fmt.Errorf("expected AES-GCM algorithm, got %s", encrypted.Algorithm)
	}

	// Validate key size
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key size: %d bytes (must be 16, 24, or 32)", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Reconstruct ciphertext with tag
	ciphertextWithTag := append(encrypted.Data, encrypted.Tag...)

	// Decrypt and verify authentication
	plaintext, err := gcm.Open(nil, encrypted.IV, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// GenerateAESKey generates a cryptographically secure random AES key.
//
// Parameters:
//   - keySize: Key size in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256)
//
// Returns:
//   - []byte: The generated AES key
//   - error: Invalid key size error
//
// Example:
//
//	key, err := symmetric.GenerateAESKey(32)  // Generate 256-bit key
//	if err != nil {
//		log.Fatal(err)
//	}
func GenerateAESKey(keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	return key, nil
}

// DeriveKeyFromPassword derives an AES key from a password using PBKDF2.
//
// This function uses PBKDF2 (Password-Based Key Derivation Function 2) with
// SHA-256 to derive a cryptographic key from a password and salt.
//
// Parameters:
//   - password: The password string
//   - salt: Random salt (at least 16 bytes recommended)
//   - keySize: Desired key size in bytes (16, 24, or 32)
//   - iterations: Number of PBKDF2 iterations (100,000 minimum recommended)
//
// Returns:
//   - []byte: The derived AES key
//   - error: Invalid parameters
//
// Security recommendations:
//   - Use a random salt of at least 16 bytes
//   - Use at least 100,000 iterations (more for higher security)
//   - Store the salt with the encrypted data for decryption
//
// Example:
//
//	salt, _ := symmetric.GenerateSalt(16)
//	key, err := symmetric.DeriveKeyFromPassword("myPassword", salt, 32, 100000)
func DeriveKeyFromPassword(password string, salt []byte, keySize int, iterations int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	if len(salt) < 8 {
		return nil, fmt.Errorf("salt too short: minimum 8 bytes required")
	}

	if iterations < 1000 {
		return nil, fmt.Errorf("iteration count too low: minimum 1000 required")
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
	return key, nil
}

// DeriveKeyFromSharedSecret derives an AES key from a shared secret using HKDF.
//
// This function uses HKDF (HMAC-based Key Derivation Function) with SHA-256
// to derive a deterministic AES key from a shared secret obtained through
// key agreement protocols like ECDH or X25519.
//
// Parameters:
//   - sharedSecret: The shared secret from key agreement
//   - info: Optional context/application-specific information
//   - keySize: Desired key size in bytes (16, 24, or 32)
//
// Returns:
//   - []byte: The derived AES key
//   - error: Invalid parameters or derivation failure
//
// Example:
//
//	// After ECDH key agreement
//	aesKey, err := symmetric.DeriveKeyFromSharedSecret(sharedSecret, []byte("encryption"), 32)
func DeriveKeyFromSharedSecret(sharedSecret []byte, info []byte, keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret cannot be empty")
	}

	hkdf := hkdf.New(sha256.New, sharedSecret, nil, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// GenerateSalt generates a cryptographically random salt.
//
// Parameters:
//   - size: Salt size in bytes (16 bytes minimum recommended)
//
// Returns:
//   - []byte: The generated salt
//   - error: Invalid size or generation failure
//
// Example:
//
//	salt, err := symmetric.GenerateSalt(16)
//	if err != nil {
//		log.Fatal(err)
//	}
func GenerateSalt(size int) ([]byte, error) {
	if size < 16 {
		return nil, fmt.Errorf("salt size too small: minimum 16 bytes recommended")
	}

	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}

// QuickEncryptSymmetric provides simple symmetric encryption with default options.
//
// Parameters:
//   - data: The plaintext data to encrypt
//   - key: The AES encryption key
//
// Returns:
//   - *encryption.EncryptedData: The encrypted data
//   - error: Any error during encryption
//
// Example:
//
//	key, _ := symmetric.GenerateAESKey(32)
//	encrypted, err := symmetric.QuickEncryptSymmetric(data, key)
func QuickEncryptSymmetric(data []byte, key []byte) (*encryption.EncryptedData, error) {
	return EncryptAESGCM(data, key, encryption.DefaultEncryptOptions())
}

// QuickDecryptSymmetric provides simple symmetric decryption with default options.
//
// Parameters:
//   - encrypted: The encrypted data
//   - key: The AES decryption key
//
// Returns:
//   - []byte: The decrypted plaintext
//   - error: Any error during decryption
//
// Example:
//
//	plaintext, err := symmetric.QuickDecryptSymmetric(encrypted, key)
func QuickDecryptSymmetric(encrypted *encryption.EncryptedData, key []byte) ([]byte, error) {
	return DecryptAESGCM(encrypted, key, encryption.DefaultDecryptOptions())
}
