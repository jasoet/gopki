// Package pkcs12 provides comprehensive utilities for creating and parsing PKCS#12 files.
//
// PKCS#12 is a binary format defined in RFC 7292 for storing cryptographic objects
// including private keys, certificates, and certificate chains in a single
// password-protected file. This format is widely used for importing/exporting
// certificates and private keys across different systems and applications.
//
// This package integrates with the existing GoPKI infrastructure to provide
// convenient import/export functionality for certificates and key pairs while
// maintaining compatibility with standard PKCS#12 implementations.
//
// Key features:
//   - Create P12 files from certificates and private keys
//   - Parse P12 files to extract certificates and private keys
//   - Support for certificate chains and multiple certificates
//   - Password protection with configurable encryption algorithms
//   - Type-safe integration with GoPKI keypair and certificate packages
//   - Validation and verification of P12 contents
//   - Quick utility functions for common operations
//   - Test P12 generation for development and testing
//
// Supported algorithms:
//   - RSA private keys (2048+ bits recommended)
//   - ECDSA private keys (all standard curves)
//   - Ed25519 private keys
//   - X.509 certificates and certificate chains
//
// Security considerations:
//   - P12 files are only as secure as their passwords
//   - Use strong passwords for production P12 files
//   - Protect P12 files during transmission and storage
//   - Consider the sensitivity of private key material
//
// Example usage:
//
//	// Basic P12 creation and loading
//	import (
//		"crypto/rsa"
//		"crypto/rand"
//		"github.com/jasoet/gopki/pkcs12"
//	)
//
//	// Generate a test P12 file
//	err := pkcs12.GenerateTestP12("test.p12", "password123")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Load the P12 file
//	container, err := pkcs12.LoadFromP12File("test.p12", pkcs12.DefaultLoadOptions("password123"))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Access the contents
//	fmt.Printf("Key type: %s\n", container.GetKeyType())
//	fmt.Printf("Certificate subject: %s\n", container.Certificate.Subject)
//
//	// Create P12 from existing materials
//	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
//	opts := pkcs12.DefaultCreateOptions("newPassword")
//	err = pkcs12.CreateP12File("new.p12", privateKey, certificate, nil, opts)
//
//	// Quick operations
//	container, err = pkcs12.QuickLoadP12("new.p12", "newPassword")
//	err = pkcs12.QuickCreateP12("quick.p12", "password", privateKey, certificate)
//
// Integration with GoPKI:
//
//	This package is designed to work seamlessly with other GoPKI packages.
//	See the keypair/p12.go and cert/p12.go files for type-safe integration
//	functions that leverage the GoPKI keypair and certificate abstractions.
package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/jasoet/gopki/keypair"
)

// P12Container represents a PKCS#12 container with its contents
type P12Container struct {
	// Private key from the P12 file
	PrivateKey keypair.GenericPrivateKey
	// Primary certificate associated with the private key
	Certificate *x509.Certificate
	// Additional certificates (certificate chain)
	CACertificates []*x509.Certificate
	// Friendly name (if available)
	FriendlyName string
}

// CreateOptions contains options for creating P12 files
type CreateOptions struct {
	// Password to encrypt the P12 file
	Password string
	// Friendly name for the certificate
	FriendlyName string
	// Include certificate chain
	IncludeChain bool
	// Legacy mode for compatibility with older systems
	LegacyMode bool
	// Additional CA certificates to include
	ExtraCAs []*x509.Certificate
}

// LoadOptions contains options for loading P12 files
type LoadOptions struct {
	// Password to decrypt the P12 file
	Password string
	// Validate certificate chain
	ValidateChain bool
	// Check certificate expiration
	CheckExpiration bool
}

// DefaultCreateOptions returns sensible default options for creating P12 files.
//
// The default configuration provides good security and compatibility:
//   - Includes certificate chain if provided
//   - Uses modern encryption (not legacy mode)
//   - No friendly name set
//   - No extra CA certificates
//
// Parameters:
//   - password: The password to encrypt the P12 file
//
// Returns:
//   - CreateOptions: A struct with default settings for P12 creation
//
// Example:
//
//	opts := pkcs12.DefaultCreateOptions("strongPassword123")
//	p12Data, err := pkcs12.CreateP12(privateKey, cert, nil, opts)
func DefaultCreateOptions(password string) CreateOptions {
	return CreateOptions{
		Password:     password,
		FriendlyName: "",
		IncludeChain: true,
		LegacyMode:   false,
		ExtraCAs:     nil,
	}
}

// DefaultLoadOptions returns safe default options for loading P12 files.
//
// The default configuration is optimized for compatibility and speed:
//   - No certificate chain validation (faster loading)
//   - No certificate expiration checking
//   - Basic password decryption only
//
// For production use, consider enabling validation options:
//
//	opts := pkcs12.DefaultLoadOptions("password")
//	opts.ValidateChain = true      // Enable chain validation
//	opts.CheckExpiration = true    // Check certificate expiration
//
// Parameters:
//   - password: The password to decrypt the P12 file
//
// Returns:
//   - LoadOptions: A struct with default settings for P12 loading
func DefaultLoadOptions(password string) LoadOptions {
	return LoadOptions{
		Password:        password,
		ValidateChain:   false,
		CheckExpiration: false,
	}
}

// CreateP12 creates PKCS#12 binary data from a private key, certificate, and optional chain using type-safe generics.
//
// This is the core function for creating P12 data. It accepts any private key type
// supported by the underlying PKCS#12 library (RSA, ECDSA, Ed25519) and combines
// it with the certificate and optional certificate chain into encrypted P12 data.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key (type-safe generic: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
//   - certificate: The X.509 certificate associated with the private key
//   - caCerts: Optional certificate chain (can be nil)
//   - opts: Creation options including password and encryption settings
//
// Returns:
//   - []byte: The P12 binary data ready for saving or transmission
//   - error: Any error that occurred during P12 creation
//
// Security notes:
//   - The private key will be encrypted with the provided password
//   - Use strong passwords as P12 security depends on password strength
//   - The resulting data should be transmitted and stored securely
//
// Example:
//
//	opts := pkcs12.DefaultCreateOptions("securePassword")
//	p12Data, err := pkcs12.CreateP12(privateKey, certificate, caCertChain, opts)
//	if err != nil {
//		log.Fatal("Failed to create P12:", err)
//	}
//	// Save to file or transmit securely
//	os.WriteFile("certificate.p12", p12Data, 0600)
func CreateP12[T keypair.PrivateKey](privateKey T, certificate *x509.Certificate, caCerts []*x509.Certificate, opts CreateOptions) ([]byte, error) {
	// Check for nil private key using reflection
	if any(privateKey) == nil || reflect.ValueOf(privateKey).IsNil() {
		return nil, fmt.Errorf("private key is required")
	}
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Combine certificate chain if requested
	var allCACerts []*x509.Certificate
	if opts.IncludeChain {
		allCACerts = append(allCACerts, caCerts...)
	}
	if len(opts.ExtraCAs) > 0 {
		allCACerts = append(allCACerts, opts.ExtraCAs...)
	}

	// Use different encoding based on legacy mode
	if opts.LegacyMode {
		// Use legacy mode for older systems
		return pkcs12.Legacy.Encode(privateKey, certificate, allCACerts, opts.Password)
	} else {
		// Use modern mode (default)
		return pkcs12.Modern.Encode(privateKey, certificate, allCACerts, opts.Password)
	}
}


// ParseP12 parses PKCS#12 data and returns the private key, certificate, and CA certificates
func ParseP12(p12Data []byte, opts LoadOptions) (*P12Container, error) {
	if len(p12Data) == 0 {
		return nil, fmt.Errorf("P12 data is empty")
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Parse the P12 data
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(p12Data, opts.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode P12 data: %w", err)
	}

	container := &P12Container{
		PrivateKey:     privateKey,
		Certificate:    certificate,
		CACertificates: caCerts,
	}

	// Validate certificate chain if requested
	if opts.ValidateChain && len(caCerts) > 0 {
		if err := validateCertificateChain(certificate, caCerts); err != nil {
			return nil, fmt.Errorf("certificate chain validation failed: %w", err)
		}
	}

	// Check certificate expiration if requested
	if opts.CheckExpiration && certificate != nil {
		if err := validateCertificateExpiration(certificate); err != nil {
			return nil, fmt.Errorf("certificate validation failed: %w", err)
		}
	}

	return container, nil
}

// CreateP12File creates a PKCS#12 file from a private key and certificate using type-safe generics.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
func CreateP12File[T keypair.PrivateKey](filename string, privateKey T, certificate *x509.Certificate, caCerts []*x509.Certificate, opts CreateOptions) error {
	// Create P12 data
	p12Data, err := CreateP12(privateKey, certificate, caCerts, opts)
	if err != nil {
		return fmt.Errorf("failed to create P12 data: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write to file with secure permissions
	if err := os.WriteFile(filename, p12Data, 0600); err != nil {
		return fmt.Errorf("failed to write P12 file %s: %w", filename, err)
	}

	return nil
}

// LoadFromP12File loads a PKCS#12 file and returns the container
func LoadFromP12File(filename string, opts LoadOptions) (*P12Container, error) {
	// Read the P12 file
	p12Data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read P12 file %s: %w", filename, err)
	}

	// Parse the P12 data
	return ParseP12(p12Data, opts)
}

// Type-safe integration functions with GoPKI packages

// Note: Integration functions with GoPKI packages are available in separate files
// to avoid import cycles. See keypair/p12.go and cert/p12.go for GoPKI integration.

// Utility functions for working with P12 containers

// ExtractCertificateChain extracts the complete certificate chain from a P12 container
func (c *P12Container) ExtractCertificateChain() []*x509.Certificate {
	chain := []*x509.Certificate{c.Certificate}
	chain = append(chain, c.CACertificates...)
	return chain
}

// GetKeyType returns the type of private key in the container
func (c *P12Container) GetKeyType() string {
	return getPrivateKeyType(c.PrivateKey)
}

// Validate performs basic validation on the P12 container contents
func (c *P12Container) Validate() error {
	if c.PrivateKey == nil {
		return fmt.Errorf("private key is missing")
	}
	if c.Certificate == nil {
		return fmt.Errorf("certificate is missing")
	}

	// Validate that private key matches certificate public key
	if err := validateKeyPairMatch(c.PrivateKey, c.Certificate.PublicKey); err != nil {
		return fmt.Errorf("private key does not match certificate: %w", err)
	}

	return nil
}

// QuickCreateP12 provides a simple interface for creating P12 files with default options using type-safe generics.
//
// This is a simplified wrapper around CreateP12File that uses default creation
// options. It's perfect for development, testing, or simple use cases where
// you don't need to customize the P12 creation settings.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
//
// Parameters:
//   - filename: Path where the P12 file will be created
//   - password: Password to protect the P12 file
//   - privateKey: The private key to include
//   - certificate: The certificate to include
//
// Returns:
//   - error: Any error that occurred during creation
//
// Example:
//
//	err := pkcs12.QuickCreateP12("my-cert.p12", "password123", privateKey, certificate)
//	if err != nil {
//		log.Fatal("Failed to create P12:", err)
//	}
func QuickCreateP12[T keypair.PrivateKey](filename, password string, privateKey T, certificate *x509.Certificate) error {
	opts := DefaultCreateOptions(password)
	return CreateP12File(filename, privateKey, certificate, nil, opts)
}

// QuickLoadP12 provides a simple interface for loading P12 files with default options
func QuickLoadP12(filename, password string) (*P12Container, error) {
	opts := DefaultLoadOptions(password)
	return LoadFromP12File(filename, opts)
}

// GenerateTestP12 generates a P12 file with a self-signed certificate for testing
func GenerateTestP12(filename, password string) error {
	// Generate RSA key pair using standard library
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create self-signed certificate template
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"GoPKI Test"},
			Country:      []string{"US"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		SerialNumber: big.NewInt(1),
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create P12 file
	opts := DefaultCreateOptions(password)
	opts.FriendlyName = "Test Certificate"

	return CreateP12File(filename, privateKey, certificate, nil, opts)
}
