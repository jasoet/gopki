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
	Type     string
	Value    interface{}
	Critical bool
}

// FormatRegistry manages available signature formats
type FormatRegistry struct {
	formats map[string]SignatureFormat
}

// NewFormatRegistry creates a new format registry.
// This function creates an empty registry that can be used to manage
// signature format implementations in isolated contexts.
//
// Returns a new FormatRegistry with no formats registered.
//
// Most applications should use the DefaultRegistry instead of creating
// custom registries, unless format isolation is specifically required.
//
// Example:
//
//	// Create a custom registry for specific formats only
//	customRegistry := NewFormatRegistry()
//	customRegistry.Register(NewRawFormat())
//	customRegistry.Register(NewPKCS7Format(false))
func NewFormatRegistry() *FormatRegistry {
	return &FormatRegistry{
		formats: make(map[string]SignatureFormat),
	}
}

// Register adds a signature format to the registry.
// This method registers a format implementation, making it available
// for lookup by name. If a format with the same name already exists,
// it will be replaced.
//
// Parameters:
//   - format: The signature format implementation to register
//
// The format is indexed by its Name() method, so each format must
// provide a unique name identifier.
//
// Example:
//
//	registry := NewFormatRegistry()
//	registry.Register(NewRawFormat())
//	registry.Register(NewPKCS7Format(false))
//	registry.Register(NewPKCS7Format(true))  // Detached version
func (r *FormatRegistry) Register(format SignatureFormat) {
	r.formats[format.Name()] = format
}

// Get retrieves a signature format by name.
// This method looks up a previously registered format implementation.
//
// Parameters:
//   - name: The name of the format to retrieve
//
// Returns the format implementation and true if found, or nil and false
// if no format with the given name is registered.
//
// Example:
//
//	format, exists := registry.Get("raw")
//	if !exists {
//		log.Printf("Raw format not available")
//		return
//	}
//
//	signature, err := format.Sign(data, signer, cert, opts)
func (r *FormatRegistry) Get(name string) (SignatureFormat, bool) {
	format, exists := r.formats[name]
	return format, exists
}

// List returns all registered format names.
// This method provides a way to discover what formats are available
// in the registry.
//
// Returns a slice of format names (strings) for all registered formats.
// The order of names is not guaranteed.
//
// This is useful for:
//   - Displaying available formats to users
//   - Iterating through all available formats
//   - Debugging registration issues
//
// Example:
//
//	formats := registry.List()
//	fmt.Printf("Available formats: %v\n", formats)
//	// Output: Available formats: [raw pkcs7 pkcs7-detached]
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
	FormatRaw           = "raw"
	FormatPKCS7         = "pkcs7"
	FormatPKCS7Detached = "pkcs7-detached"
	FormatCMS           = "cms"
	FormatCMSDetached   = "cms-detached"
)

// GetFormat is a convenience function to get a format from the default registry.
// This function provides easy access to formats registered in the global
// DefaultRegistry without needing to reference it directly.
//
// Parameters:
//   - name: The name of the format to retrieve (e.g., "raw", "pkcs7")
//
// Returns the format implementation and true if found, or nil and false
// if no format with the given name is registered in the default registry.
//
// This is the most commonly used function for accessing signature formats
// since most applications use the default registry.
//
// Example:
//
//	format, exists := GetFormat("pkcs7")
//	if !exists {
//		log.Fatal("PKCS#7 format not available")
//	}
//
//	signature, err := format.Sign(data, signer, cert, opts)
func GetFormat(name string) (SignatureFormat, bool) {
	return DefaultRegistry.Get(name)
}

// RegisterFormat is a convenience function to register a format in the default registry.
// This function provides easy registration of signature formats without needing
// to access the DefaultRegistry directly.
//
// Parameters:
//   - format: The signature format implementation to register globally
//
// The format becomes available to all code using GetFormat() or accessing
// the DefaultRegistry. If a format with the same name already exists,
// it will be replaced.
//
// This function is typically called during package initialization to register
// built-in formats or in init() functions of format implementation packages.
//
// Example:
//
//	// Register a custom format implementation
//	RegisterFormat(NewCustomFormat())
//
//	// Now it's available globally
//	format, _ := GetFormat("custom")
func RegisterFormat(format SignatureFormat) {
	DefaultRegistry.Register(format)
}

// ListFormats returns all available format names from the default registry.
// This convenience function provides easy access to discover what signature
// formats are available globally.
//
// Returns a slice of format names (strings) for all formats registered
// in the DefaultRegistry. The order is not guaranteed.
//
// This is useful for:
//   - Displaying available formats to users in CLI applications
//   - Validating format names from configuration or user input
//   - Building format selection menus in GUI applications
//
// Example:
//
//	availableFormats := ListFormats()
//	fmt.Printf("Supported signature formats: %v\n", availableFormats)
//	// Output: Supported signature formats: [raw pkcs7 pkcs7-detached]
//
//	// Validate user input
//	userFormat := "pkcs7"
//	valid := false
//	for _, format := range ListFormats() {
//		if format == userFormat {
//			valid = true
//			break
//		}
//	}
func ListFormats() []string {
	return DefaultRegistry.List()
}
