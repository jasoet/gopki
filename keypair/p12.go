package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/pkcs12"
)

// ToP12 exports a key pair to PKCS#12 format with the given certificate
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

// ToP12File exports a key pair and certificate to a PKCS#12 file
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

// FromP12 loads a key pair from PKCS#12 data
func FromP12(p12Data []byte, password string) (any, *x509.Certificate, []*x509.Certificate, error) {
	if len(p12Data) == 0 {
		return nil, nil, nil, fmt.Errorf("P12 data is required")
	}
	if password == "" {
		return nil, nil, nil, fmt.Errorf("password is required")
	}

	// Parse P12 data
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.ParseP12(p12Data, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse P12 data: %w", err)
	}

	// Convert to keypair based on private key type
	keyPair, err := createKeyPairFromPrivateKey(container.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	return keyPair, container.Certificate, container.CACertificates, nil
}

// FromP12File loads a key pair from a PKCS#12 file
func FromP12File(filename, password string) (any, *x509.Certificate, []*x509.Certificate, error) {
	if filename == "" {
		return nil, nil, nil, fmt.Errorf("filename is required")
	}
	if password == "" {
		return nil, nil, nil, fmt.Errorf("password is required")
	}

	// Load P12 file
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load P12 file: %w", err)
	}

	// Convert to keypair based on private key type
	keyPair, err := createKeyPairFromPrivateKey(container.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	return keyPair, container.Certificate, container.CACertificates, nil
}

// Type-specific P12 functions for better type safety

// ToP12RSA exports an RSA key pair to PKCS#12 format
func ToP12RSA(keyPair *algo.RSAKeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12(keyPair, certificate, password)
}

// ToP12ECDSA exports an ECDSA key pair to PKCS#12 format
func ToP12ECDSA(keyPair *algo.ECDSAKeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12(keyPair, certificate, password)
}

// ToP12Ed25519 exports an Ed25519 key pair to PKCS#12 format
func ToP12Ed25519(keyPair *algo.Ed25519KeyPair, certificate *x509.Certificate, password string) ([]byte, error) {
	return ToP12(keyPair, certificate, password)
}

// FromP12RSA loads an RSA key pair from PKCS#12 data
func FromP12RSA(p12Data []byte, password string) (*algo.RSAKeyPair, *x509.Certificate, []*x509.Certificate, error) {
	keyPair, cert, caCerts, err := FromP12(p12Data, password)
	if err != nil {
		return nil, nil, nil, err
	}

	rsaKeyPair, ok := keyPair.(*algo.RSAKeyPair)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected RSA key pair, got %T", keyPair)
	}

	return rsaKeyPair, cert, caCerts, nil
}

// FromP12ECDSA loads an ECDSA key pair from PKCS#12 data
func FromP12ECDSA(p12Data []byte, password string) (*algo.ECDSAKeyPair, *x509.Certificate, []*x509.Certificate, error) {
	keyPair, cert, caCerts, err := FromP12(p12Data, password)
	if err != nil {
		return nil, nil, nil, err
	}

	ecdsaKeyPair, ok := keyPair.(*algo.ECDSAKeyPair)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected ECDSA key pair, got %T", keyPair)
	}

	return ecdsaKeyPair, cert, caCerts, nil
}

// FromP12Ed25519 loads an Ed25519 key pair from PKCS#12 data
func FromP12Ed25519(p12Data []byte, password string) (*algo.Ed25519KeyPair, *x509.Certificate, []*x509.Certificate, error) {
	keyPair, cert, caCerts, err := FromP12(p12Data, password)
	if err != nil {
		return nil, nil, nil, err
	}

	ed25519KeyPair, ok := keyPair.(*algo.Ed25519KeyPair)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected Ed25519 key pair, got %T", keyPair)
	}

	return ed25519KeyPair, cert, caCerts, nil
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

// ImportFromP12WithValidation imports a key pair from P12 with comprehensive validation
func ImportFromP12WithValidation(filename, password string) (any, *x509.Certificate, []*x509.Certificate, error) {
	// Load with validation enabled
	opts := pkcs12.DefaultLoadOptions(password)
	opts.ValidateChain = true
	opts.CheckExpiration = true

	container, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load and validate P12: %w", err)
	}

	// Convert to keypair
	keyPair, err := createKeyPairFromPrivateKey(container.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	return keyPair, container.Certificate, container.CACertificates, nil
}

// ConvertP12ToPEM converts a P12 file to separate PEM files
func ConvertP12ToPEM(p12File, password, privateKeyFile, certFile string) error {
	// Load from P12
	keyPair, cert, _, err := FromP12File(p12File, password)
	if err != nil {
		return fmt.Errorf("failed to load P12: %w", err)
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