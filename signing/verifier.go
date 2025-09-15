package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// VerifySignature verifies a signature against the original data
func VerifySignature(data []byte, signature *Signature, opts VerifyOptions) error {
	if signature == nil {
		return fmt.Errorf("signature is nil")
	}

	if signature.Certificate == nil {
		return ErrMissingCertificate
	}

	// Verify certificate validity period unless skipped
	if !opts.SkipExpirationCheck {
		now := opts.VerifyTime
		if now.IsZero() {
			now = time.Now()
		}

		if now.Before(signature.Certificate.NotBefore) {
			return ErrCertificateNotYetValid
		}

		if now.After(signature.Certificate.NotAfter) {
			return ErrCertificateExpired
		}
	}

	// Check key usage if specified
	if opts.RequiredKeyUsage != 0 {
		if signature.Certificate.KeyUsage&opts.RequiredKeyUsage == 0 {
			return fmt.Errorf("certificate does not have required key usage")
		}
	}

	// Check extended key usage if specified
	if len(opts.RequiredExtKeyUsage) > 0 {
		hasRequiredUsage := false
		for _, required := range opts.RequiredExtKeyUsage {
			for _, usage := range signature.Certificate.ExtKeyUsage {
				if usage == required {
					hasRequiredUsage = true
					break
				}
			}
			if hasRequiredUsage {
				break
			}
		}
		if !hasRequiredUsage {
			return fmt.Errorf("certificate does not have required extended key usage")
		}
	}

	// Verify certificate chain if requested
	if opts.VerifyChain {
		if err := verifyCertificateChain(signature.Certificate, signature.CertificateChain, opts); err != nil {
			return fmt.Errorf("certificate chain verification failed: %w", err)
		}
	}

	// Compute the hash of the data
	hasher := signature.HashAlgorithm.New()
	if _, err := hasher.Write(data); err != nil {
		return fmt.Errorf("failed to hash data: %w", err)
	}
	computedDigest := hasher.Sum(nil)

	// Verify the signature based on the algorithm
	publicKey := signature.Certificate.PublicKey
	switch signature.Algorithm {
	case AlgorithmRSA:
		return verifyRSASignature(publicKey, computedDigest, signature.Data, signature.HashAlgorithm)
	case AlgorithmECDSA:
		return verifyECDSASignature(publicKey, computedDigest, signature.Data, signature.HashAlgorithm)
	case AlgorithmEd25519:
		return verifyEd25519Signature(publicKey, data, signature.Data)
	default:
		return ErrUnsupportedAlgorithm
	}
}

// VerifyWithCertificate verifies a signature using a specific certificate
func VerifyWithCertificate(data []byte, signature *Signature, certificate *x509.Certificate, opts VerifyOptions) error {
	if signature == nil {
		return fmt.Errorf("signature is nil")
	}

	if certificate == nil {
		return ErrMissingCertificate
	}

	// Temporarily replace the certificate in the signature
	originalCert := signature.Certificate
	signature.Certificate = certificate
	defer func() {
		signature.Certificate = originalCert
	}()

	return VerifySignature(data, signature, opts)
}

// VerifyDetachedSignature verifies a detached signature
func VerifyDetachedSignature(data []byte, signatureData []byte, certificate *x509.Certificate, hashAlgo crypto.Hash) error {
	if certificate == nil {
		return ErrMissingCertificate
	}

	// Determine the algorithm from the public key
	algo, err := GetSignatureAlgorithm(certificate.PublicKey)
	if err != nil {
		return err
	}

	// Create a temporary signature object
	sig := &Signature{
		Algorithm:     algo,
		HashAlgorithm: hashAlgo,
		Data:          signatureData,
		Certificate:   certificate,
	}

	return VerifySignature(data, sig, DefaultVerifyOptions())
}

// verifyRSASignature verifies an RSA signature
func verifyRSASignature(publicKey crypto.PublicKey, digest, signature []byte, hashAlgo crypto.Hash) error {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an RSA key")
	}

	err := rsa.VerifyPKCS1v15(rsaKey, hashAlgo, digest, signature)
	if err != nil {
		return ErrVerificationFailed
	}

	return nil
}

// verifyECDSASignature verifies an ECDSA signature
func verifyECDSASignature(publicKey crypto.PublicKey, digest, signature []byte, hashAlgo crypto.Hash) error {
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an ECDSA key")
	}

	// ECDSA signatures are typically DER-encoded
	// For simplicity, we'll use ecdsa.VerifyASN1
	if !ecdsa.VerifyASN1(ecdsaKey, digest, signature) {
		return ErrVerificationFailed
	}

	return nil
}

// verifyEd25519Signature verifies an Ed25519 signature
func verifyEd25519Signature(publicKey crypto.PublicKey, message, signature []byte) error {
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an Ed25519 key")
	}

	// Ed25519 verifies the message directly, not a hash
	if !ed25519.Verify(ed25519Key, message, signature) {
		return ErrVerificationFailed
	}

	return nil
}

// verifyCertificateChain verifies the certificate chain
func verifyCertificateChain(cert *x509.Certificate, chain []*x509.Certificate, opts VerifyOptions) error {
	// Create verification options
	verifyOpts := x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: opts.Intermediates,
		CurrentTime:   opts.VerifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Add chain certificates to intermediates
	if verifyOpts.Intermediates == nil && len(chain) > 0 {
		verifyOpts.Intermediates = x509.NewCertPool()
		for _, c := range chain {
			verifyOpts.Intermediates.AddCert(c)
		}
	}

	// Verify the certificate chain
	_, err := cert.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	return nil
}

// VerifyTimestamp verifies a timestamp on a signature
func VerifyTimestamp(signature *Signature, opts VerifyOptions) error {
	if signature.Timestamp == nil {
		return fmt.Errorf("signature does not have a timestamp")
	}

	// Verify the timestamp certificate
	if signature.Timestamp.Certificate != nil {
		now := opts.VerifyTime
		if now.IsZero() {
			now = time.Now()
		}

		if now.Before(signature.Timestamp.Certificate.NotBefore) {
			return fmt.Errorf("timestamp certificate is not yet valid")
		}

		if now.After(signature.Timestamp.Certificate.NotAfter) {
			return fmt.Errorf("timestamp certificate has expired")
		}
	}

	// In a full implementation, we would verify the RFC 3161 timestamp token
	// For now, we just check that the timestamp exists
	if len(signature.Timestamp.Token) == 0 {
		return ErrInvalidTimestamp
	}

	return nil
}

// Utility functions for verification

// ExtractCertificateFromSignature extracts the signer's certificate from a signature
func ExtractCertificateFromSignature(signature *Signature) (*x509.Certificate, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is nil")
	}

	if signature.Certificate == nil {
		return nil, ErrMissingCertificate
	}

	return signature.Certificate, nil
}

// ExtractCertificateChainFromSignature extracts the certificate chain from a signature
func ExtractCertificateChainFromSignature(signature *Signature) ([]*x509.Certificate, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is nil")
	}

	if len(signature.CertificateChain) == 0 {
		return nil, fmt.Errorf("signature does not contain a certificate chain")
	}

	return signature.CertificateChain, nil
}

// IsSignatureValid performs a quick validation of a signature structure
func IsSignatureValid(signature *Signature) bool {
	if signature == nil {
		return false
	}

	if len(signature.Data) == 0 {
		return false
	}

	if signature.Algorithm == "" {
		return false
	}

	if signature.HashAlgorithm == 0 {
		return false
	}

	return true
}

// GetSignatureInfo returns human-readable information about a signature
func GetSignatureInfo(signature *Signature) string {
	if signature == nil {
		return "No signature"
	}

	info := fmt.Sprintf("Algorithm: %s\n", signature.Algorithm)
	info += fmt.Sprintf("Hash: %s\n", HashAlgorithmToString(signature.HashAlgorithm))
	info += fmt.Sprintf("Format: %s\n", signature.Format)

	if signature.Certificate != nil {
		info += fmt.Sprintf("Signer: %s\n", signature.Certificate.Subject.CommonName)
		info += fmt.Sprintf("Issuer: %s\n", signature.Certificate.Issuer.CommonName)
		info += fmt.Sprintf("Valid from: %s\n", signature.Certificate.NotBefore.Format(time.RFC3339))
		info += fmt.Sprintf("Valid until: %s\n", signature.Certificate.NotAfter.Format(time.RFC3339))
	}

	if signature.Timestamp != nil {
		info += fmt.Sprintf("Timestamp: %s\n", signature.Timestamp.Time.Format(time.RFC3339))
	}

	return info
}