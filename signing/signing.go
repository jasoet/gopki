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
	// FormatRaw represents a raw signature (just the signature bytes)
	FormatRaw SignatureFormat = "raw"
	// FormatPKCS7 represents a PKCS#7/CMS signature format
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
	// Format of the signature (raw, PKCS#7, etc.)
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

// SignOptions configures the signing operation
type SignOptions struct {
	// Hash algorithm to use (default: SHA256)
	HashAlgorithm crypto.Hash
	// Signature format (default: FormatRaw)
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
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrCertificateExpired   = errors.New("certificate has expired")
	ErrCertificateNotYetValid = errors.New("certificate is not yet valid")
	ErrInvalidCertificate   = errors.New("invalid certificate")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrUnsupportedFormat    = errors.New("unsupported signature format")
	ErrMissingPrivateKey    = errors.New("missing private key")
	ErrMissingCertificate   = errors.New("missing certificate")
	ErrVerificationFailed   = errors.New("signature verification failed")
	ErrInvalidTimestamp     = errors.New("invalid timestamp")
)

// DefaultSignOptions returns default signing options
func DefaultSignOptions() SignOptions {
	return SignOptions{
		HashAlgorithm:      0, // Let the algorithm determine the default
		Format:             FormatRaw,
		IncludeCertificate: true,
		IncludeChain:       false,
		Detached:           false,
	}
}

// DefaultVerifyOptions returns default verification options
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		RequiredKeyUsage: x509.KeyUsageDigitalSignature,
		VerifyChain:      false, // Skip chain verification for self-signed certs
		VerifyTime:       time.Now(),
	}
}

// GetHashAlgorithm returns the appropriate hash algorithm for the signature algorithm
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