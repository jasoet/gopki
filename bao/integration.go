package bao

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jasoet/gopki/cert"
)

// parseCertificateFromPEM parses a PEM-encoded certificate string.
func parseCertificateFromPEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("vault: failed to decode PEM certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("vault: invalid PEM block type: %s", block.Type)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault: parse certificate: %w", err)
	}

	return certificate, nil
}

// parseCertificateChainFromPEM parses a PEM-encoded certificate chain.
// Returns a slice of certificates in order (leaf to root).
func parseCertificateChainFromPEM(pemData string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := []byte(pemData)

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("vault: parse certificate in chain: %w", err)
			}
			certificates = append(certificates, certificate)
		}

		remaining = rest
		if len(remaining) == 0 {
			break
		}
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("vault: no certificates found in PEM data")
	}

	return certificates, nil
}

// vaultCertToGoPKI converts a Vault certificate response to GoPKI Certificate.
// This validates the certificate and checks for known limitations.
func vaultCertToGoPKI(pemCert string, pemChain string) (*cert.Certificate, error) {
	// Parse the certificate
	x509Cert, err := parseCertificateFromPEM(pemCert)
	if err != nil {
		return nil, fmt.Errorf("vault: convert certificate: %w", err)
	}

	// Check for Ed25519 limitation (cannot be used for envelope encryption)
	if x509Cert.PublicKeyAlgorithm == x509.Ed25519 {
		// Note: This is documented but not an error
		// Users should be aware of this limitation from documentation
	}

	// Create GoPKI certificate
	pemData := []byte(pemCert)
	derData := x509Cert.Raw

	gopkiCert := &cert.Certificate{
		Certificate: x509Cert,
		PEMData:     pemData,
		DERData:     derData,
	}

	return gopkiCert, nil
}

// gopkiCertToPEM converts a GoPKI Certificate to PEM string.
func gopkiCertToPEM(c *cert.Certificate) string {
	return string(c.PEMData)
}

// parseCSRFromPEM parses a PEM-encoded CSR string.
func parseCSRFromPEM(pemData string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("vault: failed to decode PEM CSR")
	}

	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("vault: invalid PEM block type: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault: parse CSR: %w", err)
	}

	return csr, nil
}
