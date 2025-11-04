package pki

import (
	"fmt"

	"github.com/jasoet/gopki/cert"
)

// ============================================================================
// Certificate Request (CSR) Creation from CertificateClient
// ============================================================================

// CreateCSR creates a new Certificate Signing Request from the certificate's subject information.
// This is useful for renewing certificates or creating subordinate certificates.
// Returns an error if the key pair is not available.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	csrReq := cert.CSRRequest{
//	    Subject: certClient.Certificate().Certificate.Subject,
//	    DNSNames: []string{"app.example.com", "www.app.example.com"},
//	}
//	csr, err := certClient.CreateCSR(csrReq)
func (cc *CertificateClient[K]) CreateCSR(req cert.CSRRequest) (*cert.CertificateSigningRequest, error) {
	if !cc.HasKeyPair() {
		return nil, fmt.Errorf("bao: key pair not available for CSR creation")
	}

	kp, err := cc.KeyPair()
	if err != nil {
		return nil, fmt.Errorf("bao: get key pair: %w", err)
	}

	return cert.CreateCSR(kp, req)
}

// ============================================================================
// Helper Functions for Certificate Information
// ============================================================================

// PublicKeyAlgorithm returns the public key algorithm of the certificate.
//
// Example:
//
//	certClient, _ := client.GetRSACertificate(ctx, "serial-number")
//	algo := certClient.PublicKeyAlgorithm()
//	fmt.Printf("Algorithm: %s\n", algo) // "RSA", "ECDSA", or "Ed25519"
func (cc *CertificateClient[K]) PublicKeyAlgorithm() string {
	if cc.certificate == nil || cc.certificate.Certificate == nil {
		return ""
	}
	return cc.certificate.Certificate.PublicKeyAlgorithm.String()
}

// IsExpired checks if the certificate has expired.
//
// Example:
//
//	certClient, _ := client.GetRSACertificate(ctx, "serial-number")
//	if certClient.IsExpired() {
//	    fmt.Println("Certificate has expired")
//	}
func (cc *CertificateClient[K]) IsExpired() bool {
	if cc.certInfo == nil {
		return false
	}
	return cc.certInfo.Expiration.Before(cc.certInfo.Expiration)
}

// SerialNumber returns the certificate's serial number.
//
// Example:
//
//	certClient, _ := client.GetRSACertificate(ctx, "serial-number")
//	serial := certClient.SerialNumber()
func (cc *CertificateClient[K]) SerialNumber() string {
	if cc.certInfo == nil {
		return ""
	}
	return cc.certInfo.SerialNumber
}

