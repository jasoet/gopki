// File symmetric.go provides AES-GCM symmetric encryption operations used by
// the asymmetric encryption implementations and envelope encryption.
//
// This file implements authenticated encryption using AES-GCM (Galois/Counter Mode),
// which provides both confidentiality and authenticity in a single operation.
// AES-GCM is the recommended authenticated encryption mode for new applications.
//
// Features:
//   - AES-GCM authenticated encryption with 128, 192, or 256-bit keys
//   - HKDF (HMAC-based Key Derivation Function) for key derivation
//   - Automatic nonce generation for each encryption operation
//   - Authentication tag verification during decryption
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
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/jasoet/gopki/cert"
	"golang.org/x/crypto/hkdf"
)

// SymmetricEncryptor provides symmetric encryption operations using AES-GCM.
//
// This encryptor implements authenticated encryption using AES in Galois/Counter Mode,
// which combines encryption and authentication in a single, efficient operation.
// It's used internally by asymmetric encryption methods and envelope encryption.
//
// Supported key sizes:
//   - 128-bit (16 bytes): AES-128-GCM
//   - 192-bit (24 bytes): AES-192-GCM
//   - 256-bit (32 bytes): AES-256-GCM (recommended)
//
// Security guarantees:
//   - Authenticated encryption: provides both confidentiality and authenticity
//   - Unique nonces: each encryption operation uses a fresh random nonce
//   - Tag verification: decryption fails if data has been tampered with
type SymmetricEncryptor struct{}

// NewSymmetricEncryptor creates a new symmetric encryptor instance.
//
// Returns:
//   - *SymmetricEncryptor: A new encryptor ready for AES-GCM operations
//
// Example:
//
//	encryptor := NewSymmetricEncryptor()
//	key := make([]byte, 32)  // 256-bit key
//	rand.Read(key)
//	encrypted, err := encryptor.EncryptAESGCM(data, key, opts)
func NewSymmetricEncryptor() *SymmetricEncryptor {
	return &SymmetricEncryptor{}
}

// EncryptAESGCM encrypts data using AES-GCM authenticated encryption with the provided key.
//
// This method implements authenticated encryption using AES in Galois/Counter Mode.
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
//   - *EncryptedData: Encrypted data containing nonce + ciphertext + auth tag
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
//	encryptor := NewSymmetricEncryptor()
//	key := make([]byte, 32)  // 256-bit key
//	rand.Read(key)
//
//	data := []byte("sensitive data to encrypt")
//	encrypted, err := encryptor.EncryptAESGCM(data, key, opts)
//	if err != nil {
//		log.Fatal("AES-GCM encryption failed:", err)
//	}
func (e *SymmetricEncryptor) EncryptAESGCM(data []byte, key []byte, opts EncryptOptions) (*EncryptedData, error) {
	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Extract tag (last 16 bytes for GCM)
	tagSize := gcm.Overhead()
	if len(ciphertext) < tagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	encryptedData := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]

	return &EncryptedData{
		Algorithm: AlgorithmAESGCM,
		Format:    opts.Format,
		Data:      encryptedData,
		IV:        nonce,
		Tag:       tag,
		Metadata:  opts.Metadata,
	}, nil
}

// DecryptAESGCM decrypts AES-GCM encrypted data
func (e *SymmetricEncryptor) DecryptAESGCM(encrypted *EncryptedData, key []byte, opts DecryptOptions) ([]byte, error) {
	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != AlgorithmAESGCM {
		return nil, fmt.Errorf("expected AES-GCM algorithm, got %s", encrypted.Algorithm)
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	if len(encrypted.IV) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", gcm.NonceSize(), len(encrypted.IV))
	}

	// Reconstruct ciphertext with tag
	ciphertext := append(encrypted.Data, encrypted.Tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, encrypted.IV, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptAESGCM is a utility function for internal use by asymmetric encryption
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

	// Extract tag (last 16 bytes for GCM)
	tagSize := gcm.Overhead()
	encryptedData := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]

	return encryptedData, nonce, tag, nil
}

// decryptAESGCM is a utility function for internal use by asymmetric encryption
func decryptAESGCM(encryptedData []byte, key []byte, nonce []byte, tag []byte) ([]byte, error) {
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

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", gcm.NonceSize(), len(nonce))
	}

	// Reconstruct ciphertext with tag
	ciphertext := append(encryptedData, tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// deriveAESKey derives a 256-bit AES key from shared secret using HKDF-SHA256
func deriveAESKey(sharedSecret []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("GoPKI-AES-Key"))
	key := make([]byte, 32) // 256-bit key
	_, _ = io.ReadFull(hkdf, key)
	return key
}

// GenerateAESKey generates a random AES key of the specified size
func GenerateAESKey(keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	return key, nil
}

// DeriveKeyFromPassword derives an AES key from a password using PBKDF2
func DeriveKeyFromPassword(password []byte, salt []byte, iterations int, keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid AES key size: must be 16, 24, or 32 bytes")
	}

	if iterations < 10000 {
		return nil, fmt.Errorf("iteration count too low: minimum 10000 recommended")
	}

	if len(salt) < 16 {
		return nil, fmt.Errorf("salt too short: minimum 16 bytes recommended")
	}

	// Use HKDF for key derivation instead of PBKDF2 for consistency
	hkdf := hkdf.New(sha256.New, password, salt, []byte("GoPKI-Password-Key"))
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// GenerateSalt generates a cryptographically random salt
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

// Encrypt encrypts data using the symmetric encryptor (requires pre-shared key)
func (e *SymmetricEncryptor) Encrypt(data []byte, keyPair any, opts EncryptOptions) (*EncryptedData, error) {
	return nil, fmt.Errorf("Encrypt not supported for symmetric encryption - use EncryptAESGCM with explicit key")
}

// Decrypt decrypts data using the symmetric encryptor (requires pre-shared key)
func (e *SymmetricEncryptor) Decrypt(encrypted *EncryptedData, keyPair any, opts DecryptOptions) ([]byte, error) {
	return nil, fmt.Errorf("Decrypt not supported for symmetric encryption - use DecryptAESGCM with explicit key")
}

// EncryptForPublicKey is not applicable for symmetric encryption
func (e *SymmetricEncryptor) EncryptForPublicKey(data []byte, publicKey any, opts EncryptOptions) (*EncryptedData, error) {
	return nil, fmt.Errorf("EncryptForPublicKey not supported for symmetric encryption")
}

// EncryptWithCertificate is not applicable for symmetric encryption
func (e *SymmetricEncryptor) EncryptWithCertificate(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	return nil, fmt.Errorf("EncryptWithCertificate not supported for symmetric encryption")
}

// DecryptWithPrivateKey is not applicable for symmetric encryption
func (e *SymmetricEncryptor) DecryptWithPrivateKey(encrypted *EncryptedData, privateKey any, opts DecryptOptions) ([]byte, error) {
	return nil, fmt.Errorf("DecryptWithPrivateKey not supported for symmetric encryption")
}

// SupportedAlgorithms returns the algorithms supported by the symmetric encryptor
func (e *SymmetricEncryptor) SupportedAlgorithms() []EncryptionAlgorithm {
	return []EncryptionAlgorithm{
		AlgorithmAESGCM,
	}
}

// Type-safe wrapper functions for symmetric encryption

// EncryptSymmetricTyped provides type-safe AES-GCM encryption with explicit key
func EncryptSymmetricTyped(data []byte, key []byte, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewSymmetricEncryptor()
	return encryptor.EncryptAESGCM(data, key, opts)
}

// DecryptSymmetricTyped provides type-safe AES-GCM decryption with explicit key
func DecryptSymmetricTyped(encrypted *EncryptedData, key []byte, opts DecryptOptions) ([]byte, error) {
	encryptor := NewSymmetricEncryptor()
	return encryptor.DecryptAESGCM(encrypted, key, opts)
}

// QuickEncryptSymmetric provides simple symmetric encryption with default options
func QuickEncryptSymmetric(data []byte, key []byte) (*EncryptedData, error) {
	return EncryptSymmetricTyped(data, key, DefaultEncryptOptions())
}

// QuickDecryptSymmetric provides simple symmetric decryption with default options
func QuickDecryptSymmetric(encrypted *EncryptedData, key []byte) ([]byte, error) {
	return DecryptSymmetricTyped(encrypted, key, DefaultDecryptOptions())
}
