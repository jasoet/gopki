package pkcs12

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// validateCertificateChain validates that the certificate chain is properly ordered and valid
func validateCertificateChain(leafCert *x509.Certificate, caCerts []*x509.Certificate) error {
	if leafCert == nil {
		return fmt.Errorf("leaf certificate is required")
	}

	if len(caCerts) == 0 {
		// No chain to validate
		return nil
	}

	// Create certificate pool from CA certificates
	pool := x509.NewCertPool()
	for _, caCert := range caCerts {
		pool.AddCert(caCert)
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots: pool,
	}

	_, err := leafCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// validateCertificateExpiration checks if the certificate is currently valid
func validateCertificateExpiration(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %s)", cert.NotBefore.Format(time.RFC3339))
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired on %s)", cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// validateKeyPairMatch validates that the private key matches the certificate's public key
func validateKeyPairMatch(privateKey any, publicKey any) error {
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("private key is RSA but public key is not")
		}
		if priv.PublicKey.N.Cmp(pub.N) != 0 || priv.PublicKey.E != pub.E {
			return fmt.Errorf("RSA private key does not match public key")
		}

	case *ecdsa.PrivateKey:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("private key is ECDSA but public key is not")
		}
		if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
			return fmt.Errorf("ECDSA private key does not match public key")
		}

	case ed25519.PrivateKey:
		pub, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("private key is Ed25519 but public key is not")
		}
		expectedPub := priv.Public().(ed25519.PublicKey)
		if !expectedPub.Equal(pub) {
			return fmt.Errorf("Ed25519 private key does not match public key")
		}

	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	return nil
}

// getPrivateKeyType returns a string description of the private key type
func getPrivateKeyType(privateKey any) string {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown (%T)", privateKey)
	}
}

// createKeyPairFromPrivateKey is available in keypair/p12.go for GoPKI integration

// GetCertificateInfo extracts useful information from a certificate for display purposes
func GetCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	if cert == nil {
		return nil
	}

	info := map[string]interface{}{
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"serial":      cert.SerialNumber.String(),
		"not_before":  cert.NotBefore.Format(time.RFC3339),
		"not_after":   cert.NotAfter.Format(time.RFC3339),
		"is_ca":       cert.IsCA,
		"key_usage":   getKeyUsageStrings(cert.KeyUsage),
		"ext_key_usage": getExtKeyUsageStrings(cert.ExtKeyUsage),
	}

	if len(cert.DNSNames) > 0 {
		info["dns_names"] = cert.DNSNames
	}

	if len(cert.EmailAddresses) > 0 {
		info["email_addresses"] = cert.EmailAddresses
	}

	if len(cert.IPAddresses) > 0 {
		info["ip_addresses"] = cert.IPAddresses
	}

	return info
}

// getKeyUsageStrings converts key usage flags to human-readable strings
func getKeyUsageStrings(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// getExtKeyUsageStrings converts extended key usage values to human-readable strings
func getExtKeyUsageStrings(extUsage []x509.ExtKeyUsage) []string {
	var usages []string

	for _, usage := range extUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown (%d)", int(usage)))
		}
	}

	return usages
}

// ValidateP12File performs comprehensive validation on a P12 file
func ValidateP12File(filename, password string) error {
	// Load the P12 file
	container, err := LoadFromP12File(filename, LoadOptions{
		Password:        password,
		ValidateChain:   true,
		CheckExpiration: true,
	})
	if err != nil {
		return fmt.Errorf("failed to load P12 file: %w", err)
	}

	// Validate container contents
	if err := container.Validate(); err != nil {
		return fmt.Errorf("P12 container validation failed: %w", err)
	}

	return nil
}

// ConvertP12ToGoPKI is available in keypair/p12.go for GoPKI integration