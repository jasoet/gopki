package pki

import (
	"fmt"
	"os"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// CertificateClient - Format Conversion Methods
// ============================================================================

// ToPEM converts the certificate to PEM format.
// Returns the certificate in PEM-encoded bytes.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	pemBytes, err := certClient.ToPEM()
//	os.WriteFile("cert.pem", pemBytes, 0644)
func (cc *CertificateClient[K]) ToPEM() ([]byte, error) {
	if cc.certificate == nil {
		return nil, fmt.Errorf("bao: certificate not available")
	}
	return cc.certificate.ToPEM(), nil
}

// ToDER converts the certificate to DER format.
// Returns the certificate in DER-encoded bytes.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	derBytes, err := certClient.ToDER()
//	os.WriteFile("cert.der", derBytes, 0644)
func (cc *CertificateClient[K]) ToDER() ([]byte, error) {
	if cc.certificate == nil {
		return nil, fmt.Errorf("bao: certificate not available")
	}
	return cc.certificate.ToDER(), nil
}

// ExportPEM exports both certificate and private key as PEM bytes.
// Returns an error if the key pair is not available.
//
// This is useful for saving certificate bundles or transmitting them securely.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	certPEM, keyPEM, err := certClient.ExportPEM()
//	if err != nil {
//	    // Key not available
//	}
func (cc *CertificateClient[K]) ExportPEM() (certPEM, keyPEM []byte, err error) {
	if !cc.HasKeyPair() {
		return nil, nil, fmt.Errorf("bao: key pair not available")
	}

	// Get certificate PEM
	certPEM, err = cc.ToPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("bao: convert certificate to PEM: %w", err)
	}

	// Get key pair and convert to PEM
	kp, err := cc.KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("bao: get key pair: %w", err)
	}

	// Get private key PEM based on type
	switch k := any(kp).(type) {
	case *algo.RSAKeyPair:
		keyPEM, err = k.PrivateKeyToPEM()
	case *algo.ECDSAKeyPair:
		keyPEM, err = k.PrivateKeyToPEM()
	case *algo.Ed25519KeyPair:
		keyPEM, err = k.PrivateKeyToPEM()
	default:
		return nil, nil, fmt.Errorf("bao: unsupported key pair type: %T", kp)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("bao: convert private key to PEM: %w", err)
	}

	return certPEM, keyPEM, nil
}

// SaveToFiles saves the certificate and private key to separate files.
// The certificate is saved with 0644 permissions, and the private key with secure 0600 permissions.
// Returns an error if the key pair is not available.
//
// This follows gopki's security best practices for file permissions.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	err := certClient.SaveToFiles("cert.pem", "key.pem")
func (cc *CertificateClient[K]) SaveToFiles(certPath, keyPath string) error {
	if !cc.HasKeyPair() {
		return fmt.Errorf("bao: key pair not available")
	}

	// Export PEM data
	certPEM, keyPEM, err := cc.ExportPEM()
	if err != nil {
		return err
	}

	// Save private key first with secure permissions (0600)
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("bao: save private key: %w", err)
	}

	// Save certificate with standard permissions (0644)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		// Clean up private key if certificate save fails
		os.Remove(keyPath)
		return fmt.Errorf("bao: save certificate: %w", err)
	}

	return nil
}

// SaveCertificate saves the certificate to a file in PEM format.
// The certificate is saved with 0644 permissions.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	err := certClient.SaveCertificate("cert.pem")
func (cc *CertificateClient[K]) SaveCertificate(path string) error {
	if cc.certificate == nil {
		return fmt.Errorf("bao: certificate not available")
	}

	// Get certificate PEM
	certPEM, err := cc.ToPEM()
	if err != nil {
		return err
	}

	// Save with standard certificate permissions
	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		return fmt.Errorf("bao: save certificate: %w", err)
	}

	return nil
}

// ============================================================================
// KeyClient - Format Conversion Methods
// ============================================================================

// SaveKeyPairToFiles saves the key pair to separate PEM files using gopki's secure patterns.
// The private key is saved with 0600 permissions, public key with 0644 permissions.
// Returns an error if the key pair is not available.
//
// Example:
//
//	keyClient, _ := client.GenerateRSAKey(ctx, &GenerateKeyOptions{...})
//	err := keyClient.SaveKeyPairToFiles("private.pem", "public.pem")
func (kc *KeyClient[K]) SaveKeyPairToFiles(privatePath, publicPath string) error {
	if !kc.HasKeyPair() {
		return fmt.Errorf("bao: key pair not available")
	}

	kp, err := kc.KeyPair()
	if err != nil {
		return fmt.Errorf("bao: get key pair: %w", err)
	}

	// Get private and public key PEM based on type
	var privPEM, pubPEM []byte
	switch k := any(kp).(type) {
	case *algo.RSAKeyPair:
		privPEM, err = k.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert private key to PEM: %w", err)
		}
		pubPEM, err = k.PublicKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert public key to PEM: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privPEM, err = k.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert private key to PEM: %w", err)
		}
		pubPEM, err = k.PublicKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert public key to PEM: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privPEM, err = k.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert private key to PEM: %w", err)
		}
		pubPEM, err = k.PublicKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert public key to PEM: %w", err)
		}
	default:
		return fmt.Errorf("bao: unsupported key pair type: %T", kp)
	}

	// Save private key with secure permissions (0600)
	if err := os.WriteFile(privatePath, privPEM, 0600); err != nil {
		return fmt.Errorf("bao: save private key: %w", err)
	}

	// Save public key with standard permissions (0644)
	if err := os.WriteFile(publicPath, pubPEM, 0644); err != nil {
		// Clean up private key if public key save fails
		os.Remove(privatePath)
		return fmt.Errorf("bao: save public key: %w", err)
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// ParseCertificateFromPEM is a helper to parse a PEM-encoded certificate.
// This is useful when working with certificates from external sources.
//
// Example:
//
//	pemData, _ := os.ReadFile("cert.pem")
//	goPKICert, err := pki.ParseCertificateFromPEM(pemData)
func ParseCertificateFromPEM(pemData []byte) (*cert.Certificate, error) {
	return cert.ParseCertificateFromPEM(pemData)
}

// ParseCertificateFromDER parses a DER-encoded certificate.
//
// Example:
//
//	derData, _ := os.ReadFile("cert.der")
//	goPKICert, err := pki.ParseCertificateFromDER(derData)
func ParseCertificateFromDER(derData []byte) (*cert.Certificate, error) {
	return cert.ParseCertificateFromDER(derData)
}
