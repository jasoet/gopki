// Package encryption provides comprehensive, type-safe data encryption and decryption functionality
// that seamlessly integrates with the GoPKI keypair and certificate infrastructure.
//
// This package extends the GoPKI ecosystem by providing production-ready encryption capabilities
// using the same type-safe design patterns. It supports multiple cryptographic algorithms,
// various data sizes, and different output formats while maintaining compatibility with
// existing PKI workflows.
//
// Key Features:
//   - Type-safe encryption with Go generics integration
//   - Multiple encryption algorithms with automatic selection
//   - Support for both small and large data encryption
//   - Certificate-based encryption workflows
//   - Configurable output formats (Raw, PKCS#7, CMS)
//   - Envelope encryption for large data sets
//   - Comprehensive error handling and validation
//
// Supported Algorithms:
//   - RSA-OAEP: Direct RSA encryption (recommended for keys ≥2048 bits)
//   - ECDH + AES-GCM: ECDSA key agreement with symmetric encryption
//   - X25519 + AES-GCM: Ed25519-based key agreement with symmetric encryption
//   - AES-GCM: Direct symmetric encryption for envelope encryption
//
// Data Size Recommendations:
//   - Small data (≤190 bytes for RSA-2048): Direct RSA-OAEP encryption
//   - Medium data (≤8KB): ECDH/X25519 + AES-GCM
//   - Large data (>8KB): Envelope encryption (recommended)
//
// Output Formats:
//   - Raw: Binary format with magic bytes for format identification
//   - PKCS#7: Standard ASN.1 DER-encoded format
//   - CMS: Cryptographic Message Syntax format
//
// Security Considerations:
//   - All encryption uses authenticated encryption (AES-GCM)
//   - RSA-OAEP provides semantic security for RSA encryption
//   - Key agreement protocols use ephemeral keys for forward secrecy
//   - Random nonces and IVs are generated for each encryption operation
//
// Basic Usage Examples:
//
//	// Generate keys using existing GoPKI infrastructure
//	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Simple data encryption
//	data := []byte("sensitive information")
//	encrypted, err := EncryptData(data, rsaKeys, DefaultEncryptOptions())
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt the data
//	decrypted, err := DecryptData(encrypted, rsaKeys, DefaultDecryptOptions())
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Large file encryption using envelope encryption
//	opts := DefaultEncryptOptions()
//	opts.UseEnvelopeEncryption = true
//	opts.Format = FormatRaw
//
//	largeData := make([]byte, 1024*1024) // 1MB data
//	encrypted, err = EncryptData(largeData, rsaKeys, opts)
//
// Certificate-based Encryption:
//
//	// Load certificate from file
//	cert, err := cert.LoadCertificateFromFile("recipient.pem")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Encrypt for certificate recipient
//	encrypted, err := EncryptForCertificate(data, cert, DefaultEncryptOptions())
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Advanced Usage with Custom Options:
//
//	// Create custom encryption options
//	opts := EncryptOptions{
//		Algorithm:             AlgorithmAuto,  // Auto-select based on key type
//		UseEnvelopeEncryption: true,           // Use envelope encryption for large data
//		Format:                FormatPKCS7,    // Use PKCS#7 output format
//		KeyDerivationRounds:   100000,         // Custom KDF rounds
//	}
//
//	// Encrypt with custom options
//	encrypted, err := EncryptData(largeData, keyPair, opts)
//
// Integration with Other GoPKI Packages:
//   This package is designed to work seamlessly with:
//   - keypair: For key generation and management
//   - cert: For certificate-based encryption workflows
//   - pkcs12: For importing/exporting encrypted key stores
//   - signing: For combined sign-then-encrypt workflows
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
// Currently only CMS (RFC 5652) format is supported
type EncryptionFormat string

const (
	FormatCMS EncryptionFormat = "cms" // RFC 5652 Cryptographic Message Syntax
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
	// Additional fields for ECDSA/Ed25519 support
	// Ephemeral public key (for ECDH/X25519)
	EphemeralKey []byte
	// IV for key encryption (for AES-GCM)
	KeyIV []byte
	// Authentication tag for key encryption (for AES-GCM)
	KeyTag []byte
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
		Format:             FormatCMS, // CMS is the only supported format
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
	case FormatCMS:
		// Valid format - only CMS is supported
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

// EncodeData encodes EncryptedData to CMS format bytes
// Since CMS is the only supported format, this is a convenience function
func EncodeData(data *EncryptedData) ([]byte, error) {
	if data == nil {
		return nil, errors.New("encrypted data is nil")
	}
	return EncodeToCMS(data)
}

// DecodeData decodes CMS format bytes back to EncryptedData
// Since CMS is the only supported format, this is a convenience function
func DecodeData(data []byte) (*EncryptedData, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	return DecodeFromCMS(data)
}

// ValidateEncodedData validates that the data is in valid CMS format
func ValidateEncodedData(data []byte) error {
	return ValidateCMS(data)
}
