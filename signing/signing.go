// Package signing provides document signing and signature verification functionality
// using certificates and various cryptographic algorithms (RSA, ECDSA, Ed25519).
package signing

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"
)

// SignatureFormat represents the format of a digital signature
type SignatureFormat string

const (
	// FormatPKCS7 represents a PKCS#7/CMS signature format (attached)
	FormatPKCS7 SignatureFormat = "pkcs7"
	// FormatPKCS7Detached represents a detached PKCS#7/CMS signature
	FormatPKCS7Detached SignatureFormat = "pkcs7-detached"
)

// SignatureAlgorithm represents the algorithm used for signing
type SignatureAlgorithm string

const (
	AlgorithmRSA     SignatureAlgorithm = "RSA"
	AlgorithmECDSA   SignatureAlgorithm = "ECDSA"
	AlgorithmEd25519 SignatureAlgorithm = "Ed25519"
)

// Signature represents a digital signature with its metadata
type Signature struct {
	// Format of the signature (PKCS#7, CMS, etc.)
	Format SignatureFormat
	// Algorithm used for signing
	Algorithm SignatureAlgorithm
	// Hash algorithm used (SHA256, SHA384, SHA512)
	HashAlgorithm crypto.Hash
	// The actual signature bytes
	Data []byte
	// Original data digest (hash)
	Digest []byte
	// Signer's certificate
	Certificate *x509.Certificate
	// Certificate chain (optional)
	CertificateChain []*x509.Certificate
	// Timestamp information (optional)
	Timestamp *Timestamp
	// Additional metadata
	Metadata map[string]interface{}
}

// Timestamp represents a cryptographic timestamp from a Time Stamping Authority
type Timestamp struct {
	// Time when the signature was created
	Time time.Time
	// TSA certificate
	Certificate *x509.Certificate
	// Timestamp token (RFC 3161)
	Token []byte
	// Hash algorithm used by TSA
	HashAlgorithm crypto.Hash
}

// SignatureInfo contains parsed signature information from PKCS#7 signatures
type SignatureInfo struct {
	// Signature algorithm used (e.g., "PKCS#7")
	Algorithm string
	// Hash algorithm used
	HashAlgorithm crypto.Hash
	// Signer's certificate
	Certificate *x509.Certificate
	// Certificate chain
	CertificateChain []*x509.Certificate
	// Timestamp information
	Timestamp *Timestamp
	// Additional attributes
	Attributes map[string]interface{}
	// Whether this is a detached signature
	Detached bool
}

// SignOptions configures the signing operation
type SignOptions struct {
	// Hash algorithm to use (default: SHA256)
	HashAlgorithm crypto.Hash
	// Signature format (default: FormatPKCS7)
	Format SignatureFormat
	// Include signer's certificate in signature
	IncludeCertificate bool
	// Include certificate chain in signature
	IncludeChain bool
	// Create detached signature (data not included)
	Detached bool
	// Timestamp server URL (optional)
	TimestampURL string
	// Additional attributes to include
	Attributes map[string]interface{}
	// Additional certificates to include
	ExtraCertificates []*x509.Certificate
}

// VerifyOptions configures the verification operation
type VerifyOptions struct {
	// Required certificate purposes (e.g., digitalSignature)
	RequiredKeyUsage x509.KeyUsage
	// Required extended key usage (e.g., codeSignature)
	RequiredExtKeyUsage []x509.ExtKeyUsage
	// Verify certificate chain
	VerifyChain bool
	// Root certificates for chain verification
	Roots *x509.CertPool
	// Intermediate certificates for chain verification
	Intermediates *x509.CertPool
	// Time to verify certificate validity (default: now)
	VerifyTime time.Time
	// Skip expiration check
	SkipExpirationCheck bool
}

// Common errors
var (
	ErrInvalidSignature       = errors.New("invalid signature")
	ErrCertificateExpired     = errors.New("certificate has expired")
	ErrCertificateNotYetValid = errors.New("certificate is not yet valid")
	ErrInvalidCertificate     = errors.New("invalid certificate")
	ErrUnsupportedAlgorithm   = errors.New("unsupported algorithm")
	ErrUnsupportedFormat      = errors.New("unsupported signature format")
	ErrMissingPrivateKey      = errors.New("missing private key")
	ErrMissingCertificate     = errors.New("missing certificate")
	ErrVerificationFailed     = errors.New("signature verification failed")
	ErrInvalidTimestamp       = errors.New("invalid timestamp")
)

// DefaultSignOptions returns default signing options with secure defaults.
// These options are suitable for most signing scenarios and provide a good
// balance between security and compatibility.
//
// Default values:
//   - HashAlgorithm: 0 (auto-selected based on key algorithm and size)
//   - Format: FormatPKCS7 (industry-standard PKCS#7/CMS format)
//   - IncludeCertificate: true (includes signer's certificate)
//   - IncludeChain: false (certificate chain not included)
//   - Detached: false (signature includes the data)
//
// Returns SignOptions with secure default values.
//
// Example:
//
//	opts := DefaultSignOptions()
//	opts.Format = FormatPKCS7  // Override format if needed
//	signature, err := SignDocument(data, keyPair, cert, opts)
func DefaultSignOptions() SignOptions {
	return SignOptions{
		HashAlgorithm:      0, // Let the algorithm determine the default
		Format:             FormatPKCS7,
		IncludeCertificate: true,
		IncludeChain:       false,
		Detached:           false,
	}
}

// DefaultVerifyOptions returns default verification options with secure defaults.
// These options provide basic signature verification without requiring complex
// certificate chain validation, making them suitable for simple use cases.
//
// Default values:
//   - RequiredKeyUsage: x509.KeyUsageDigitalSignature (requires digital signature capability)
//   - VerifyChain: false (skips certificate chain verification for self-signed certificates)
//   - VerifyTime: time.Now() (verifies certificate validity at current time)
//   - SkipExpirationCheck: false (enforces certificate validity period)
//
// For production environments with proper PKI infrastructure, consider enabling
// chain verification and providing root/intermediate certificate pools.
//
// Returns VerifyOptions with secure default values.
//
// Example:
//
//	opts := DefaultVerifyOptions()
//	opts.VerifyChain = true              // Enable chain verification
//	opts.Roots = rootCertPool            // Add trusted root certificates
//	err := VerifySignature(data, signature, opts)
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		RequiredKeyUsage: x509.KeyUsageDigitalSignature,
		VerifyChain:      false, // Skip chain verification for self-signed certs
		VerifyTime:       time.Now(),
	}
}

// GetHashAlgorithm returns the appropriate hash algorithm for the signature algorithm.
// It selects the hash algorithm based on the signing algorithm and key size for optimal security.
//
// Algorithm recommendations:
//   - RSA: SHA-256 for keys < 3072 bits, SHA-384 for keys >= 3072 bits
//   - ECDSA: SHA-256 for P-256/P-224, SHA-384 for P-384, SHA-512 for P-521
//   - Ed25519: SHA-512 (used internally by Ed25519)
//
// Parameters:
//   - algo: The signature algorithm (RSA, ECDSA, or Ed25519)
//   - keySize: The key size in bits
//
// Returns the recommended crypto.Hash for the given algorithm and key size.
//
// Example:
//
//	hash := GetHashAlgorithm(AlgorithmRSA, 2048)  // Returns crypto.SHA256
//	hash = GetHashAlgorithm(AlgorithmRSA, 4096)   // Returns crypto.SHA384
func GetHashAlgorithm(algo SignatureAlgorithm, keySize int) crypto.Hash {
	switch algo {
	case AlgorithmRSA:
		if keySize >= 3072 {
			return crypto.SHA384
		}
		return crypto.SHA256
	case AlgorithmECDSA:
		if keySize >= 384 {
			return crypto.SHA384
		}
		return crypto.SHA256
	case AlgorithmEd25519:
		// Ed25519 uses SHA-512 internally
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}
