// Package keypair provides PKCS#12 (P12) integration for the GoPKI keypair package.
// This file implements P12 import/export functionality with type-safe operations
// that integrate seamlessly with the existing keypair abstractions.
//
// P12 files (PKCS#12) are a standard format for storing cryptographic materials
// including private keys, certificates, and certificate chains in a single
// password-protected file. This implementation provides both generic and
// algorithm-specific functions for maximum flexibility and type safety.
//
// Example usage:
//
//	// Generate a key pair
//	keyPair, err := algo.GenerateRSAKeyPair(2048)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create a self-signed certificate
//	cert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
//		Subject: pkix.Name{CommonName: "example.com"},
//		ValidFor: 365 * 24 * time.Hour,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Export to P12 format
//	p12Data, err := ToP12(keyPair, cert.Certificate, "password123")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Save to file
//	err = ToP12File(keyPair, cert.Certificate, "keystore.p12", "password123")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Load from P12 file
//	loadedKeyPair, loadedCert, caCerts, err := FromP12File("keystore.p12", "password123")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// The package supports all key algorithms available in GoPKI:
//   - RSA (2048+ bits recommended)
//   - ECDSA (P-224, P-256, P-384, P-521)
//   - Ed25519
//
// Type-safe algorithm-specific functions are provided for scenarios where
// you know the exact key type:
//   - ToP12RSA/FromP12RSA for RSA keys
//   - ToP12ECDSA/FromP12ECDSA for ECDSA keys
//   - ToP12Ed25519/FromP12Ed25519 for Ed25519 keys
package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/pkcs12"
)

// ToP12 exports a key pair to PKCS#12 format with the given certificate.
//
// This generic function accepts any KeyPair type (RSA, ECDSA, or Ed25519) and
// creates a password-protected P12 byte array containing the private key and
// certificate. The function uses default P12 creation options which provide
// good security for most use cases.
//
// Parameters:
//   - keyPair: The keypair to export (must implement KeyPair interface)
//   - certificate: The X.509 certificate associated with the key pair
//   - password: Password to protect the P12 file (cannot be empty)
//
// Returns:
//   - []byte: The P12 data that can be saved to a file or transmitted
//   - error: Any error that occurred during the export process
//
// Example:
//
//	rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
//	cert, _ := cert.CreateSelfSignedCertificate(rsaKeys, request)
//	p12Data, err := ToP12(rsaKeys, cert.Certificate, "securePassword")
//	if err != nil {
//		log.Fatal("Failed to create P12:", err)
//	}
//
// Security considerations:
//   - Use a strong password as P12 security depends on password strength
//   - The resulting P12 data should be transmitted securely
//   - Consider the sensitivity of the private key material
func ToP12[T KeyPair](keyPair T, certificate *x509.Certificate, password string) ([]byte, error) {
	if keyPair == nil {
		return nil, fmt.Errorf("key pair is required")
	}
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Extract private key from key pair
	var privateKey any
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", keyPair)
	}

	// Create P12 with default options
	opts := pkcs12.DefaultCreateOptions(password)
	return pkcs12.CreateP12(privateKey, certificate, nil, opts)
}

// ToP12File exports a key pair and certificate to a PKCS#12 file.
//
// This is a convenience function that wraps ToP12 and writes the result
// directly to a file. The file will be created with appropriate permissions
// (0600) to protect the private key material.
//
// Parameters:
//   - keyPair: The keypair to export (any KeyPair type)
//   - certificate: The X.509 certificate associated with the key pair
//   - filename: Path where the P12 file should be created
//   - password: Password to protect the P12 file
//
// Returns:
//   - error: Any error that occurred during export or file creation
//
// Example:
//
//	err := ToP12File(keyPair, cert.Certificate, "/path/to/keystore.p12", "password")
//	if err != nil {
//		log.Fatal("Failed to save P12 file:", err)
//	}
//
// The function will create any necessary parent directories and set
// restrictive file permissions to protect the private key.
func ToP12File[T KeyPair](keyPair T, certificate *x509.Certificate, filename, password string) error {
	if keyPair == nil {
		return fmt.Errorf("key pair is required")
	}
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}

	// Extract private key from key pair
	var privateKey any
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
	default:
		return fmt.Errorf("unsupported key pair type: %T", keyPair)
	}

	// Create P12 file with default options
	opts := pkcs12.DefaultCreateOptions(password)
	return pkcs12.CreateP12File(filename, privateKey, certificate, nil, opts)
}

// FromP12 loads a key pair from PKCS#12 data.
//
// This generic function parses P12 binary data and extracts the private key, certificate,
// and any CA certificates. The private key is automatically converted to the
// appropriate GoPKI KeyPair type based on its algorithm.
//
// Type Parameters:
//   - T: The expected KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - p12Data: The P12 binary data to parse
//   - password: Password to decrypt the P12 data
//
// Returns:
//   - T: The extracted key pair of the specified type
//   - *x509.Certificate: The main certificate from the P12
//   - []*x509.Certificate: Any CA certificates included in the P12
//   - error: Any error that occurred during parsing
//
// Example:
//
//	p12Data, _ := os.ReadFile("keystore.p12")
//	keyPair, cert, caCerts, err := FromP12[*algo.RSAKeyPair](p12Data, "password")
//	if err != nil {
//		log.Fatal("Failed to parse P12:", err)
//	}
//	fmt.Printf("RSA key size: %d bits\n", keyPair.PrivateKey.N.BitLen())
//
// The function automatically detects the key algorithm and returns the
// appropriate GoPKI KeyPair type for seamless integration with other
// GoPKI functions.
func FromP12[T KeyPair](p12Data []byte, password string) (T, *x509.Certificate, []*x509.Certificate, error) {
	var zero T
	if len(p12Data) == 0 {
		return zero, nil, nil, fmt.Errorf("P12 data is required")
	}
	if password == "" {
		return zero, nil, nil, fmt.Errorf("password is required")
	}

	// Parse P12 data
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.ParseP12(p12Data, opts)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to parse P12 data: %w", err)
	}

	// Convert to keypair based on private key type
	keyPair, err := createKeyPairFromPrivateKey(container.PrivateKey)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	// Type assert to the expected type
	typedKeyPair, ok := keyPair.(T)
	if !ok {
		return zero, nil, nil, fmt.Errorf("expected key pair type %T, got %T", zero, keyPair)
	}

	return typedKeyPair, container.Certificate, container.CACertificates, nil
}

// FromP12File loads a key pair from a PKCS#12 file.
//
// This generic function loads P12 file and extracts the private key, certificate,
// and any CA certificates. The private key is automatically converted to the
// appropriate GoPKI KeyPair type based on its algorithm.
//
// Type Parameters:
//   - T: The expected KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - filename: Path to the P12 file to load
//   - password: Password to decrypt the P12 file
//
// Returns:
//   - T: The extracted key pair of the specified type
//   - *x509.Certificate: The main certificate from the P12
//   - []*x509.Certificate: Any CA certificates included in the P12
//   - error: Any error that occurred during loading
//
// Example:
//
//	keyPair, cert, caCerts, err := FromP12File[*algo.RSAKeyPair]("keystore.p12", "password")
//	if err != nil {
//		log.Fatal("Failed to load P12 file:", err)
//	}
func FromP12File[T KeyPair](filename, password string) (T, *x509.Certificate, []*x509.Certificate, error) {
	var zero T
	if filename == "" {
		return zero, nil, nil, fmt.Errorf("filename is required")
	}
	if password == "" {
		return zero, nil, nil, fmt.Errorf("password is required")
	}

	// Load P12 file
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to load P12 file: %w", err)
	}

	// Convert to keypair based on private key type
	keyPair, err := createKeyPairFromPrivateKey(container.PrivateKey)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	// Type assert to the expected type
	typedKeyPair, ok := keyPair.(T)
	if !ok {
		return zero, nil, nil, fmt.Errorf("expected key pair type %T, got %T", zero, keyPair)
	}

	return typedKeyPair, container.Certificate, container.CACertificates, nil
}

// Type-specific P12 functions for better type safety
//
// The following functions provide algorithm-specific P12 operations with
// compile-time type safety. Use these when you know the exact key algorithm
// and want stronger type guarantees.

// ToP12RSA exports an RSA key pair to PKCS#12 format.
//
// This is a type-safe wrapper around ToP12 specifically for RSA keys.
// Use this when you have an RSA key pair and want compile-time type safety.
//
// Parameters:
//   - keyPair: The RSA key pair to export
//   - certificate: The X.509 certificate for the RSA key
//   - password: Password to protect the P12 file
//
// Returns:
//   - []byte: The P12 data containing the RSA key and certificate
//   - error: Any error that occurred during export
func ToP12RSA(keyPair *algo.RSAKeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12(keyPair, certificate, password)
}

// ToP12ECDSA exports an ECDSA key pair to PKCS#12 format.
//
// Type-safe wrapper for ECDSA keys supporting all curves (P-224, P-256, P-384, P-521).
func ToP12ECDSA(keyPair *algo.ECDSAKeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12(keyPair, certificate, password)
}

// ToP12Ed25519 exports an Ed25519 key pair to PKCS#12 format.
//
// Type-safe wrapper for Ed25519 keys, providing modern elliptic curve cryptography.
func ToP12Ed25519(keyPair *algo.Ed25519KeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12(keyPair, certificate, password)
}

// FromP12RSA loads an RSA key pair from PKCS#12 data
func FromP12RSA(p12Data []byte, password string) (*algo.RSAKeyPair, *x509.Certificate, []*x509.Certificate, error) {
	return FromP12[*algo.RSAKeyPair](p12Data, password)
}

// FromP12ECDSA loads an ECDSA key pair from PKCS#12 data
func FromP12ECDSA(p12Data []byte, password string) (*algo.ECDSAKeyPair, *x509.Certificate, []*x509.Certificate, error) {
	return FromP12[*algo.ECDSAKeyPair](p12Data, password)
}

// FromP12Ed25519 loads an Ed25519 key pair from PKCS#12 data
func FromP12Ed25519(p12Data []byte, password string) (*algo.Ed25519KeyPair, *x509.Certificate, []*x509.Certificate, error) {
	return FromP12[*algo.Ed25519KeyPair](p12Data, password)
}

// Helper function to create key pair from private key
func createKeyPairFromPrivateKey(privateKey any) (any, error) {
	switch priv := privateKey.(type) {
	case *algo.RSAKeyPair:
		// Already a keypair, return as-is
		return priv, nil
	case *algo.ECDSAKeyPair:
		// Already a keypair, return as-is
		return priv, nil
	case *algo.Ed25519KeyPair:
		// Already a keypair, return as-is
		return priv, nil
	default:
		// Try to create from standard crypto types
		return createKeyPairFromStandardKey(privateKey)
	}
}

// createKeyPairFromStandardKey creates a keypair from standard Go crypto types
func createKeyPairFromStandardKey(privateKey any) (any, error) {
	switch priv := privateKey.(type) {
	case *algo.RSAKeyPair:
		return priv, nil
	case *algo.ECDSAKeyPair:
		return priv, nil
	case *algo.Ed25519KeyPair:
		return priv, nil
	case *rsa.PrivateKey:
		return &algo.RSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}, nil
	case *ecdsa.PrivateKey:
		return &algo.ECDSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}, nil
	case ed25519.PrivateKey:
		publicKey := priv.Public().(ed25519.PublicKey)
		return &algo.Ed25519KeyPair{
			PrivateKey: priv,
			PublicKey:  publicKey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type for keypair creation: %T", privateKey)
	}
}

// P12Utils provides utility functions for working with P12 files and keypairs
type P12Utils struct{}

// ExportKeyPairWithChain exports a key pair with a certificate chain to P12 format
func ExportKeyPairWithChain[T KeyPair](keyPair T, certificate *x509.Certificate, caCerts []*x509.Certificate, filename, password string) error {
	if keyPair == nil {
		return fmt.Errorf("key pair is required")
	}
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}

	// Extract private key from key pair
	var privateKey any
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
	default:
		return fmt.Errorf("unsupported key pair type: %T", keyPair)
	}

	// Create P12 with certificate chain
	opts := pkcs12.DefaultCreateOptions(password)
	opts.IncludeChain = true
	return pkcs12.CreateP12File(filename, privateKey, certificate, caCerts, opts)
}

// ImportFromP12WithValidation imports a key pair from P12 with comprehensive validation.
//
// This generic function loads P12 file with comprehensive validation including
// certificate chain validation and expiration checking.
//
// Type Parameters:
//   - T: The expected KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - filename: Path to the P12 file to load
//   - password: Password to decrypt the P12 file
//
// Returns:
//   - T: The extracted key pair of the specified type
//   - *x509.Certificate: The main certificate from the P12
//   - []*x509.Certificate: Any CA certificates included in the P12
//   - error: Any error that occurred during loading or validation
//
// Example:
//
//	keyPair, cert, caCerts, err := ImportFromP12WithValidation[*algo.RSAKeyPair]("keystore.p12", "password")
//	if err != nil {
//		log.Fatal("Failed to load and validate P12 file:", err)
//	}
func ImportFromP12WithValidation[T KeyPair](filename, password string) (T, *x509.Certificate, []*x509.Certificate, error) {
	var zero T
	// Load with validation enabled
	opts := pkcs12.DefaultLoadOptions(password)
	opts.ValidateChain = true
	opts.CheckExpiration = true

	container, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to load and validate P12: %w", err)
	}

	// Convert to keypair
	keyPair, err := createKeyPairFromPrivateKey(container.PrivateKey)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	// Type assert to the expected type
	typedKeyPair, ok := keyPair.(T)
	if !ok {
		return zero, nil, nil, fmt.Errorf("expected key pair type %T, got %T", zero, keyPair)
	}

	return typedKeyPair, container.Certificate, container.CACertificates, nil
}

// ConvertP12ToPEM converts a P12 file to separate PEM files.
// This function automatically detects the key pair type in the P12 file.
func ConvertP12ToPEM(p12File, password, privateKeyFile, certFile string) error {
	// Read P12 file
	p12Data, err := os.ReadFile(p12File)
	if err != nil {
		return fmt.Errorf("failed to read P12 file: %w", err)
	}

	// Try each key pair type until one works
	var keyPair any
	var cert *x509.Certificate

	// Try RSA first
	if rsaKeyPair, rsaCert, _, rsaErr := FromP12RSA(p12Data, password); rsaErr == nil {
		keyPair = rsaKeyPair
		cert = rsaCert
	} else {
		// Try ECDSA
		if ecdsaKeyPair, ecdsaCert, _, ecdsaErr := FromP12ECDSA(p12Data, password); ecdsaErr == nil {
			keyPair = ecdsaKeyPair
			cert = ecdsaCert
		} else {
			// Try Ed25519
			if ed25519KeyPair, ed25519Cert, _, ed25519Err := FromP12Ed25519(p12Data, password); ed25519Err == nil {
				keyPair = ed25519KeyPair
				cert = ed25519Cert
			} else {
				return fmt.Errorf("failed to load P12 with any key type - RSA: %v, ECDSA: %v, Ed25519: %v", rsaErr, ecdsaErr, ed25519Err)
			}
		}
	}

	// Save as PEM files
	if privateKeyFile != "" {
		// Convert keyPair back to the correct type for ToFiles
		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			if err := ToFiles(kp, privateKeyFile, privateKeyFile+".pub"); err != nil {
				return fmt.Errorf("failed to save RSA key pair to PEM: %w", err)
			}
		case *algo.ECDSAKeyPair:
			if err := ToFiles(kp, privateKeyFile, privateKeyFile+".pub"); err != nil {
				return fmt.Errorf("failed to save ECDSA key pair to PEM: %w", err)
			}
		case *algo.Ed25519KeyPair:
			if err := ToFiles(kp, privateKeyFile, privateKeyFile+".pub"); err != nil {
				return fmt.Errorf("failed to save Ed25519 key pair to PEM: %w", err)
			}
		default:
			return fmt.Errorf("unsupported key pair type for PEM conversion: %T", keyPair)
		}
	}

	if certFile != "" {
		// Save certificate to PEM file
		if err := saveCertificateToPEM(cert, certFile); err != nil {
			return fmt.Errorf("failed to save certificate to PEM: %w", err)
		}
	}

	return nil
}

// saveCertificateToPEM saves a certificate to a PEM file
func saveCertificateToPEM(cert *x509.Certificate, filename string) error {
	// This would use cert package functionality to save the certificate
	// For now, return a placeholder error indicating this needs cert package integration
	return fmt.Errorf("certificate saving requires cert package integration - use pkcs12.GetCertificateInfo for now")
}