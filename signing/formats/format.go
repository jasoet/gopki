// Package formats provides signature format implementations including PKCS#7/CMS
package formats

import (
	"crypto"
	"crypto/x509"
	"time"
)

// SignatureFormat represents the interface that all signature formats must implement
type SignatureFormat interface {
	// Name returns the format name
	Name() string

	// Sign creates a signature in this format
	Sign(data []byte, signer crypto.Signer, cert *x509.Certificate, opts SignOptions) ([]byte, error)

	// Verify verifies a signature in this format
	Verify(data []byte, signatureData []byte, cert *x509.Certificate, opts VerifyOptions) error

	// Parse extracts signature information from the format
	Parse(signatureData []byte) (*SignatureInfo, error)

	// SupportsDetached returns true if the format supports detached signatures
	SupportsDetached() bool
}

// SignOptions contains options for signature creation
type SignOptions struct {
	// Hash algorithm to use
	HashAlgorithm crypto.Hash

	// Include the signing certificate
	IncludeCertificate bool

	// Include certificate chain
	IncludeChain bool

	// Additional certificates to include
	ExtraCertificates []*x509.Certificate

	// Create detached signature (content not included)
	Detached bool

	// Timestamp URL for RFC 3161 timestamps
	TimestampURL string

	// Custom attributes to include
	Attributes map[string]interface{}
}

// VerifyOptions contains options for signature verification
type VerifyOptions struct {
	// Root certificates for chain verification
	Roots *x509.CertPool

	// Intermediate certificates for chain verification
	Intermediates *x509.CertPool

	// Time to verify certificate validity (default: now)
	VerifyTime time.Time

	// Skip certificate chain verification
	SkipChainVerification bool

	// Skip timestamp verification
	SkipTimestampVerification bool

	// Required certificate key usage
	RequiredKeyUsage x509.KeyUsage

	// Required extended key usage
	RequiredExtKeyUsage []x509.ExtKeyUsage
}

// SignatureInfo contains parsed signature information
type SignatureInfo struct {
	// Signature algorithm used
	Algorithm string

	// Hash algorithm used
	HashAlgorithm crypto.Hash

	// Signer's certificate
	Certificate *x509.Certificate

	// Certificate chain
	CertificateChain []*x509.Certificate

	// Timestamp information
	Timestamp *TimestampInfo

	// Additional attributes
	Attributes map[string]interface{}

	// Whether this is a detached signature
	Detached bool
}

// TimestampInfo contains timestamp authority information
type TimestampInfo struct {
	// Time when signature was created
	Time time.Time

	// TSA certificate
	TSACertificate *x509.Certificate

	// Hash algorithm used by TSA
	HashAlgorithm crypto.Hash

	// Timestamp token (RFC 3161)
	Token []byte
}

// SignatureAttribute represents a custom attribute in a signature
type SignatureAttribute struct {
	Type   string
	Value  interface{}
	Critical bool
}

// FormatRegistry manages available signature formats
type FormatRegistry struct {
	formats map[string]SignatureFormat
}

// NewFormatRegistry creates a new format registry
func NewFormatRegistry() *FormatRegistry {
	return &FormatRegistry{
		formats: make(map[string]SignatureFormat),
	}
}

// Register adds a format to the registry
func (r *FormatRegistry) Register(format SignatureFormat) {
	r.formats[format.Name()] = format
}

// Get retrieves a format by name
func (r *FormatRegistry) Get(name string) (SignatureFormat, bool) {
	format, exists := r.formats[name]
	return format, exists
}

// List returns all registered format names
func (r *FormatRegistry) List() []string {
	names := make([]string, 0, len(r.formats))
	for name := range r.formats {
		names = append(names, name)
	}
	return names
}

// Default registry instance
var DefaultRegistry = NewFormatRegistry()

// Common format constants
const (
	FormatRaw            = "raw"
	FormatPKCS7          = "pkcs7"
	FormatPKCS7Detached  = "pkcs7-detached"
	FormatCMS            = "cms"
	FormatCMSDetached    = "cms-detached"
)

// GetFormat is a convenience function to get a format from the default registry
func GetFormat(name string) (SignatureFormat, bool) {
	return DefaultRegistry.Get(name)
}

// RegisterFormat is a convenience function to register a format in the default registry
func RegisterFormat(format SignatureFormat) {
	DefaultRegistry.Register(format)
}

// ListFormats returns all available format names
func ListFormats() []string {
	return DefaultRegistry.List()
}