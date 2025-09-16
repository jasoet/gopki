// Package pkcs12 provides utilities for creating and parsing PKCS#12 files.
// PKCS#12 is a binary format for storing cryptographic objects including
// private keys, certificates, and certificate chains in a single encrypted file.
//
// This package integrates with the existing GoPKI infrastructure to provide
// convenient import/export functionality for certificates and key pairs.
//
// Key features:
//   - Create P12 files from certificates and private keys
//   - Parse P12 files to extract certificates and private keys
//   - Support for certificate chains and multiple certificates
//   - Password protection and encryption
//   - Type-safe integration with GoPKI keypair and certificate packages
//
// Example usage:
//
//	// Create a P12 file
//	err := CreateP12File("signing.p12", "password", keyPair, certificate, chain)
//
//	// Load from a P12 file
//	keyPair, cert, chain, err := LoadFromP12File("signing.p12", "password")
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
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// P12Container represents a PKCS#12 container with its contents
type P12Container struct {
	// Private key from the P12 file
	PrivateKey any
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

// DefaultCreateOptions returns default options for creating P12 files
func DefaultCreateOptions(password string) CreateOptions {
	return CreateOptions{
		Password:     password,
		FriendlyName: "",
		IncludeChain: true,
		LegacyMode:   false,
		ExtraCAs:     nil,
	}
}

// DefaultLoadOptions returns default options for loading P12 files
func DefaultLoadOptions(password string) LoadOptions {
	return LoadOptions{
		Password:        password,
		ValidateChain:   false,
		CheckExpiration: false,
	}
}

// CreateP12 creates a PKCS#12 data from a private key, certificate, and optional chain
func CreateP12(privateKey any, certificate *x509.Certificate, caCerts []*x509.Certificate, opts CreateOptions) ([]byte, error) {
	if privateKey == nil {
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

// CreateP12File creates a PKCS#12 file from a private key and certificate
func CreateP12File(filename string, privateKey any, certificate *x509.Certificate, caCerts []*x509.Certificate, opts CreateOptions) error {
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

// QuickCreateP12 provides a simple interface for creating P12 files with default options
func QuickCreateP12(filename, password string, privateKey any, certificate *x509.Certificate) error {
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