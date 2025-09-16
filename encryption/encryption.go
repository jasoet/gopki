// Package encryption provides comprehensive data encryption and decryption functionality
// using the existing keypair and certificate infrastructure. It supports multiple algorithms
// (RSA, ECDSA with ECDH, Ed25519 with X25519) and various encryption formats.
//
// The package follows the same type-safe design patterns as the keypair package,
// using Go generics for compile-time type safety and consistency.
//
// Supported encryption methods:
//   - RSA-OAEP: Direct RSA encryption for small data
//   - ECDH + AES-GCM: ECDSA key agreement with symmetric encryption
//   - X25519 + AES-GCM: Ed25519-based key agreement with symmetric encryption
//   - Envelope Encryption: Hybrid approach for large data
//
// Example usage:
//
//	// Generate keys using existing infrastructure
//	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Encrypt data
//	encrypted, err := EncryptData(data, rsaKeys, DefaultEncryptOptions())
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt data
//	decrypted, err := DecryptData(encrypted, rsaKeys, DefaultDecryptOptions())
package encryption

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/jasoet/gopki/cert"
)

// EncryptionAlgorithm represents the algorithm used for encryption
type EncryptionAlgorithm string

const (
	AlgorithmRSAOAEP  EncryptionAlgorithm = "RSA-OAEP"
	AlgorithmECDH     EncryptionAlgorithm = "ECDH"
	AlgorithmX25519   EncryptionAlgorithm = "X25519"
	AlgorithmAESGCM   EncryptionAlgorithm = "AES-GCM"
	AlgorithmEnvelope EncryptionAlgorithm = "Envelope"
)

// EncryptionFormat represents the format of encrypted data
type EncryptionFormat string

const (
	FormatRaw   EncryptionFormat = "raw"
	FormatCMS   EncryptionFormat = "cms"
	FormatPKCS7 EncryptionFormat = "pkcs7"
)

// EncryptedData represents encrypted data with its metadata
type EncryptedData struct {
	// Algorithm used for encryption
	Algorithm EncryptionAlgorithm
	// Format of the encrypted data
	Format EncryptionFormat
	// The encrypted data bytes
	Data []byte
	// Encrypted symmetric key (for envelope encryption)
	EncryptedKey []byte
	// Initialization vector (for AES-GCM)
	IV []byte
	// Authentication tag (for AES-GCM)
	Tag []byte
	// Key derivation parameters (optional)
	KDF *KDFParams
	// Recipient information
	Recipients []*RecipientInfo
	// Timestamp when encrypted
	Timestamp time.Time
	// Additional metadata
	Metadata map[string]interface{}
}

// RecipientInfo contains information about an encryption recipient
type RecipientInfo struct {
	// Recipient's certificate (optional)
	Certificate *x509.Certificate
	// Key identifier
	KeyID []byte
	// Encrypted key for this recipient
	EncryptedKey []byte
	// Key encryption algorithm
	KeyEncryptionAlgorithm EncryptionAlgorithm
}

// KDFParams contains key derivation function parameters
type KDFParams struct {
	// Algorithm (PBKDF2, scrypt, etc.)
	Algorithm string
	// Salt
	Salt []byte
	// Iterations (for PBKDF2)
	Iterations int
	// Key length
	KeyLength int
	// Additional parameters
	Params map[string]interface{}
}

// EncryptOptions contains options for encryption operations
type EncryptOptions struct {
	// Encryption algorithm to use
	Algorithm EncryptionAlgorithm
	// Output format
	Format EncryptionFormat
	// Include recipient certificate
	IncludeCertificate bool
	// Additional recipients for multi-recipient encryption
	Recipients []any
	// Key derivation function parameters
	KDF *KDFParams
	// Custom metadata
	Metadata map[string]interface{}
}

// DecryptOptions contains options for decryption operations
type DecryptOptions struct {
	// Expected algorithm (for validation)
	ExpectedAlgorithm EncryptionAlgorithm
	// Verify timestamp
	VerifyTimestamp bool
	// Maximum age for encrypted data
	MaxAge time.Duration
	// Time to verify certificate validity (default: now)
	VerifyTime time.Time
	// Skip expiration check
	SkipExpirationCheck bool
	// Additional validation options
	ValidationOptions map[string]interface{}
}

// Encryptor interface for encryption operations using existing keypair abstractions
// Internal interface uses any for flexibility, but public APIs use generic constraints
type Encryptor interface {
	// Encrypt data using a key pair (internal - use public APIs)
	Encrypt(data []byte, keyPair any, opts EncryptOptions) (*EncryptedData, error)
	// Encrypt data for a specific public key (internal - use public APIs)
	EncryptForPublicKey(data []byte, publicKey any, opts EncryptOptions) (*EncryptedData, error)
	// Encrypt data using a certificate
	EncryptWithCertificate(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error)
	// Get supported algorithms
	SupportedAlgorithms() []EncryptionAlgorithm
}

// Decryptor interface for decryption operations using existing keypair abstractions
// Internal interface uses any for flexibility, but public APIs use generic constraints
type Decryptor interface {
	// Decrypt data using a key pair (internal - use public APIs)
	Decrypt(encrypted *EncryptedData, keyPair any, opts DecryptOptions) ([]byte, error)
	// Decrypt data using a private key (internal - use public APIs)
	DecryptWithPrivateKey(encrypted *EncryptedData, privateKey any, opts DecryptOptions) ([]byte, error)
	// Get supported algorithms
	SupportedAlgorithms() []EncryptionAlgorithm
}

// MultiRecipientEncryptor interface for multi-recipient encryption
// Internal interface uses any for flexibility, but public APIs use generic constraints
type MultiRecipientEncryptor interface {
	// Encrypt for multiple recipients (internal - use public APIs)
	EncryptForRecipients(data []byte, recipients []any, opts EncryptOptions) (*EncryptedData, error)
	// Add recipient to existing encrypted data (internal - use public APIs)
	AddRecipient(encrypted *EncryptedData, recipient any) error
}

// Common error types
var (
	ErrUnsupportedAlgorithm = errors.New("unsupported encryption algorithm")
	ErrUnsupportedFormat    = errors.New("unsupported encryption format")
	ErrInvalidKey           = errors.New("invalid encryption key")
	ErrDecryptionFailed     = errors.New("decryption failed")
	ErrDataTooLarge         = errors.New("data too large for encryption method")
	ErrInvalidRecipient     = errors.New("invalid recipient information")
	ErrExpiredData          = errors.New("encrypted data has expired")
	ErrInvalidFormat        = errors.New("invalid encrypted data format")
	ErrInvalidParameters    = errors.New("invalid encryption parameters")
)

// DefaultEncryptOptions returns default encryption options
func DefaultEncryptOptions() EncryptOptions {
	return EncryptOptions{
		Algorithm:          AlgorithmEnvelope,
		Format:             FormatRaw,
		IncludeCertificate: false,
		Recipients:         nil,
		KDF:                nil,
		Metadata:           make(map[string]interface{}),
	}
}

// DefaultDecryptOptions returns default decryption options
func DefaultDecryptOptions() DecryptOptions {
	return DecryptOptions{
		ExpectedAlgorithm:   "",
		VerifyTimestamp:     false,
		MaxAge:              24 * time.Hour,
		VerifyTime:          time.Time{}, // Zero time means use current time
		SkipExpirationCheck: false,
		ValidationOptions:   make(map[string]interface{}),
	}
}

// GetAlgorithmForKeyType determines the appropriate encryption algorithm for a key type
func GetAlgorithmForKeyType(keyType string) EncryptionAlgorithm {
	switch keyType {
	case "RSA":
		return AlgorithmRSAOAEP
	case "ECDSA":
		return AlgorithmECDH
	case "Ed25519":
		return AlgorithmX25519
	default:
		return AlgorithmEnvelope
	}
}

// ValidateEncryptOptions validates encryption options
func ValidateEncryptOptions(opts EncryptOptions) error {
	switch opts.Algorithm {
	case AlgorithmRSAOAEP, AlgorithmECDH, AlgorithmX25519, AlgorithmAESGCM, AlgorithmEnvelope:
		// Valid algorithms
	default:
		return ErrUnsupportedAlgorithm
	}

	switch opts.Format {
	case FormatRaw, FormatCMS, FormatPKCS7:
		// Valid formats
	default:
		return ErrUnsupportedFormat
	}

	return nil
}

// ValidateDecryptOptions validates decryption options
func ValidateDecryptOptions(opts DecryptOptions) error {
	if opts.MaxAge < 0 {
		return ErrInvalidParameters
	}
	return nil
}
