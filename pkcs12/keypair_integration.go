// Package pkcs12 provides PKCS#12 (P12) keypair integration for the GoPKI project.
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
//	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create a self-signed certificate
//	cert, err := cert.CreateSelfSignedCertificate(rsaKeys, cert.CertificateRequest{
//		Subject: pkix.Name{CommonName: "example.com"},
//		ValidFor: 365 * 24 * time.Hour,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Export to P12 format
//	p12Data, err := pkcs12.ToP12KeyPair(rsaKeys, cert.Certificate, "password123")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Save to file
//	err = pkcs12.ToP12KeyPairFile(rsaKeys, cert.Certificate, "keystore.p12", "password123")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Load from P12 file
//	loadedKeyPair, loadedCert, caCerts, err := pkcs12.FromP12KeyPairFile[*algo.RSAKeyPair]("keystore.p12", "password123")
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
//   - ToP12RSAKeyPair/FromP12RSAKeyPair for RSA keys
//   - ToP12ECDSAKeyPair/FromP12ECDSAKeyPair for ECDSA keys
//   - ToP12Ed25519KeyPair/FromP12Ed25519KeyPair for Ed25519 keys
package pkcs12

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// ToP12KeyPair exports a key pair to PKCS#12 format with the given certificate.
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
//	rsaKeys, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//	cert, _ := cert.CreateSelfSignedCertificate(rsaKeys, request)
//	p12Data, err := pkcs12.ToP12KeyPair(rsaKeys, cert.Certificate, "securePassword")
//	if err != nil {
//		log.Fatal("Failed to create P12:", err)
//	}
//
// Security considerations:
//   - Use a strong password as P12 security depends on password strength
//   - The resulting P12 data should be transmitted securely
//   - Consider the sensitivity of the private key material
func ToP12KeyPair[T keypair.KeyPair](keyPair T, certificate *x509.Certificate, password string) ([]byte, error) {
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
	// Create P12 with default options
	opts := DefaultCreateOptions(password)

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		return CreateP12(kp.PrivateKey, certificate, nil, opts)
	case *algo.ECDSAKeyPair:
		return CreateP12(kp.PrivateKey, certificate, nil, opts)
	case *algo.Ed25519KeyPair:
		return CreateP12(kp.PrivateKey, certificate, nil, opts)
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// ToP12KeyPairFile exports a key pair and certificate to a PKCS#12 file.
//
// This is a convenience function that wraps ToP12KeyPair and writes the result
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
//	err := pkcs12.ToP12KeyPairFile(keyPair, cert.Certificate, "/path/to/keystore.p12", "password")
//	if err != nil {
//		log.Fatal("Failed to save P12 file:", err)
//	}
//
// The function will create any necessary parent directories and set
// restrictive file permissions to protect the private key.
func ToP12KeyPairFile[T keypair.KeyPair](keyPair T, certificate *x509.Certificate, filename, password string) error {
	if keyPair == nil {
		return fmt.Errorf("key pair is required")
	}
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}

	// Create P12 file with default options
	opts := DefaultCreateOptions(password)

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		return CreateP12File(filename, kp.PrivateKey, certificate, nil, opts)
	case *algo.ECDSAKeyPair:
		return CreateP12File(filename, kp.PrivateKey, certificate, nil, opts)
	case *algo.Ed25519KeyPair:
		return CreateP12File(filename, kp.PrivateKey, certificate, nil, opts)
	default:
		return fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// FromP12KeyPair loads a key pair from PKCS#12 data.
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
//	keyPair, cert, caCerts, err := pkcs12.FromP12KeyPair[*algo.RSAKeyPair](p12Data, "password")
//	if err != nil {
//		log.Fatal("Failed to parse P12:", err)
//	}
//	fmt.Printf("RSA key size: %d bits\n", keyPair.PrivateKey.N.BitLen())
//
// The function automatically detects the key algorithm and returns the
// appropriate GoPKI KeyPair type for seamless integration with other
// GoPKI functions.
func FromP12KeyPair[T keypair.KeyPair](p12Data []byte, password string) (T, *x509.Certificate, []*x509.Certificate, error) {
	var zero T
	if len(p12Data) == 0 {
		return zero, nil, nil, fmt.Errorf("P12 data is required")
	}
	if password == "" {
		return zero, nil, nil, fmt.Errorf("password is required")
	}

	// Parse P12 data
	opts := DefaultLoadOptions(password)
	container, err := ParseP12(p12Data, opts)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to parse P12 data: %w", err)
	}

	// Convert to keypair based on private key type
	keyPair, err := createKeyPairFromPrivateKeyAny(container.PrivateKey)
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

// FromP12KeyPairFile loads a key pair from a PKCS#12 file.
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
//	keyPair, cert, caCerts, err := pkcs12.FromP12KeyPairFile[*algo.RSAKeyPair]("keystore.p12", "password")
//	if err != nil {
//		log.Fatal("Failed to load P12 file:", err)
//	}
func FromP12KeyPairFile[T keypair.KeyPair](filename, password string) (T, *x509.Certificate, []*x509.Certificate, error) {
	var zero T
	if filename == "" {
		return zero, nil, nil, fmt.Errorf("filename is required")
	}
	if password == "" {
		return zero, nil, nil, fmt.Errorf("password is required")
	}

	// Load P12 file
	opts := DefaultLoadOptions(password)
	container, err := LoadFromP12File(filename, opts)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to load P12 file: %w", err)
	}

	// Convert to keypair based on private key type
	keyPair, err := createKeyPairFromPrivateKeyAny(container.PrivateKey)
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

// ToP12RSAKeyPair exports an RSA key pair to PKCS#12 format.
//
// This is a type-safe wrapper around ToP12KeyPair specifically for RSA keys.
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
func ToP12RSAKeyPair(keyPair *algo.RSAKeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12KeyPair(keyPair, certificate, password)
}

// ToP12ECDSAKeyPair exports an ECDSA key pair to PKCS#12 format.
//
// Type-safe wrapper for ECDSA keys supporting all curves (P-224, P-256, P-384, P-521).
func ToP12ECDSAKeyPair(keyPair *algo.ECDSAKeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12KeyPair(keyPair, certificate, password)
}

// ToP12Ed25519KeyPair exports an Ed25519 key pair to PKCS#12 format.
//
// Type-safe wrapper for Ed25519 keys, providing modern elliptic curve cryptography.
func ToP12Ed25519KeyPair(keyPair *algo.Ed25519KeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12KeyPair(keyPair, certificate, password)
}

// FromP12RSAKeyPair loads an RSA key pair from PKCS#12 data
func FromP12RSAKeyPair(p12Data []byte, password string) (*algo.RSAKeyPair, *x509.Certificate, []*x509.Certificate, error) {
	return FromP12KeyPair[*algo.RSAKeyPair](p12Data, password)
}

// FromP12ECDSAKeyPair loads an ECDSA key pair from PKCS#12 data
func FromP12ECDSAKeyPair(p12Data []byte, password string) (*algo.ECDSAKeyPair, *x509.Certificate, []*x509.Certificate, error) {
	return FromP12KeyPair[*algo.ECDSAKeyPair](p12Data, password)
}

// FromP12Ed25519KeyPair loads an Ed25519 key pair from PKCS#12 data
func FromP12Ed25519KeyPair(p12Data []byte, password string) (*algo.Ed25519KeyPair, *x509.Certificate, []*x509.Certificate, error) {
	return FromP12KeyPair[*algo.Ed25519KeyPair](p12Data, password)
}

// ExportKeyPairWithChain exports a key pair with a certificate chain to P12 format
func ExportKeyPairWithChain[T keypair.KeyPair](keyPair T, certificate *x509.Certificate, caCerts []*x509.Certificate, filename, password string) error {
	if keyPair == nil {
		return fmt.Errorf("key pair is required")
	}
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}

	// Create P12 with certificate chain
	opts := DefaultCreateOptions(password)
	opts.IncludeChain = true

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		return CreateP12File(filename, kp.PrivateKey, certificate, caCerts, opts)
	case *algo.ECDSAKeyPair:
		return CreateP12File(filename, kp.PrivateKey, certificate, caCerts, opts)
	case *algo.Ed25519KeyPair:
		return CreateP12File(filename, kp.PrivateKey, certificate, caCerts, opts)
	default:
		return fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// ImportFromP12KeyPairWithValidation imports a key pair from P12 with comprehensive validation.
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
//	keyPair, cert, caCerts, err := pkcs12.ImportFromP12KeyPairWithValidation[*algo.RSAKeyPair]("keystore.p12", "password")
//	if err != nil {
//		log.Fatal("Failed to load and validate P12 file:", err)
//	}
func ImportFromP12KeyPairWithValidation[T keypair.KeyPair](filename, password string) (T, *x509.Certificate, []*x509.Certificate, error) {
	var zero T
	// Load with validation enabled
	opts := DefaultLoadOptions(password)
	opts.ValidateChain = true
	opts.CheckExpiration = true

	container, err := LoadFromP12File(filename, opts)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("failed to load and validate P12: %w", err)
	}

	// Convert to keypair
	keyPair, err := createKeyPairFromPrivateKeyAny(container.PrivateKey)
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

// ConvertP12KeyPairToPEM converts a P12 file to separate PEM files.
// This function automatically detects the key pair type in the P12 file.
func ConvertP12KeyPairToPEM(p12File, password, privateKeyFile, certFile string) error {
	// Read P12 file
	p12Data, err := os.ReadFile(p12File)
	if err != nil {
		return fmt.Errorf("failed to read P12 file: %w", err)
	}

	// Try each key pair type until one works
	var keyPair any
	var cert *x509.Certificate

	// Try RSA first
	if rsaKeyPair, rsaCert, _, rsaErr := FromP12RSAKeyPair(p12Data, password); rsaErr == nil {
		keyPair = rsaKeyPair
		cert = rsaCert
	} else {
		// Try ECDSA
		if ecdsaKeyPair, ecdsaCert, _, ecdsaErr := FromP12ECDSAKeyPair(p12Data, password); ecdsaErr == nil {
			keyPair = ecdsaKeyPair
			cert = ecdsaCert
		} else {
			// Try Ed25519
			if ed25519KeyPair, ed25519Cert, _, ed25519Err := FromP12Ed25519KeyPair(p12Data, password); ed25519Err == nil {
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
			if err := keypair.ToFiles(kp, privateKeyFile, privateKeyFile+".pub"); err != nil {
				return fmt.Errorf("failed to save RSA key pair to PEM: %w", err)
			}
		case *algo.ECDSAKeyPair:
			if err := keypair.ToFiles(kp, privateKeyFile, privateKeyFile+".pub"); err != nil {
				return fmt.Errorf("failed to save ECDSA key pair to PEM: %w", err)
			}
		case *algo.Ed25519KeyPair:
			if err := keypair.ToFiles(kp, privateKeyFile, privateKeyFile+".pub"); err != nil {
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

// createKeyPairFromPrivateKeyAny creates a keypair from any private key type
func createKeyPairFromPrivateKeyAny(privateKey keypair.GenericPrivateKey) (any, error) {
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		return createKeyPairFromPrivateKey(priv)
	case *ecdsa.PrivateKey:
		return createKeyPairFromPrivateKey(priv)
	case ed25519.PrivateKey:
		return createKeyPairFromPrivateKey(priv)
	default:
		return nil, fmt.Errorf("unsupported private key type for keypair creation: %T", privateKey)
	}
}

// Helper function to create key pair from private key
func createKeyPairFromPrivateKey[T keypair.PrivateKey](privateKey T) (any, error) {
	switch priv := any(privateKey).(type) {
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


// saveCertificateToPEM saves a certificate to a PEM file
func saveCertificateToPEM(cert *x509.Certificate, filename string) error {
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}
	if filename == "" {
		return fmt.Errorf("filename is required")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Encode certificate as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Write to file
	if err := os.WriteFile(filename, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write PEM file: %w", err)
	}

	return nil
}
