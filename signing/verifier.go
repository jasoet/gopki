package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/smallstep/pkcs7"

	internalcrypto "github.com/jasoet/gopki/internal/crypto"
)

// VerifySignature verifies a signature against the original data.
// This is the primary function for signature verification, providing comprehensive
// validation of both the cryptographic signature and certificate properties.
//
// The function performs the following validation steps:
//  1. Certificate validity period check (unless skipped)
//  2. Certificate key usage validation
//  3. Certificate extended key usage validation
//  4. Certificate chain verification (if enabled)
//  5. Cryptographic signature verification
//
// Supported signature algorithms:
//   - RSA with PKCS#1 v1.5 padding
//   - ECDSA with ASN.1 DER encoding
//   - Ed25519 with native format
//
// Parameters:
//   - data: The original data that was signed
//   - signature: The signature to verify (must contain certificate)
//   - opts: Verification options controlling validation behavior
//
// Returns nil if the signature is valid and all checks pass,
// or an error describing the validation failure.
//
// Common verification failures:
//   - ErrCertificateExpired: Certificate validity period has expired
//   - ErrCertificateNotYetValid: Certificate validity period has not started
//   - ErrVerificationFailed: Cryptographic signature verification failed
//   - ErrMissingCertificate: No certificate provided in signature
//
// Example:
//
//	opts := DefaultVerifyOptions()
//	opts.VerifyChain = true
//	opts.Roots = trustedRootCerts
//
//	err := VerifySignature(originalData, signature, opts)
//	if err != nil {
//		log.Printf("Signature verification failed: %v", err)
//		return
//	}
//
//	fmt.Println("Signature is valid and trusted")
func VerifySignature(data []byte, signature *Signature, opts VerifyOptions) error {
	if signature == nil {
		return fmt.Errorf("signature is nil")
	}

	if signature.Certificate == nil {
		return ErrMissingCertificate
	}

	// Verify certificate validity period
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

	// Use PKCS#7 verification for all algorithms including Ed25519
	switch signature.Format {
	case FormatPKCS7, FormatPKCS7Detached:
		// Check if this is an Ed25519 PKCS#7 signature (RFC 8419 ASN.1 format)
		if isEd25519, err := internalcrypto.IsEd25519PKCS7(signature.Data); err == nil && isEd25519 {
			// Use RFC 8419 Ed25519 PKCS#7 verification
			return verifyEd25519PKCS7Signature(data, signature)
		}
		// Use standard PKCS#7 verification for RSA and ECDSA
		return verifyPKCS7SignatureFormat(data, signature, opts)
	default:
		return fmt.Errorf("unsupported signature format: %s", signature.Format)
	}
}

// VerifyWithCertificate verifies a signature using a specific certificate.
// This function allows verification when the certificate is provided separately
// from the signature, or when you want to verify against a different certificate
// than the one embedded in the signature.
//
// This is useful for scenarios where:
//   - Signatures are detached and don't contain certificates
//   - You want to verify against a known trusted certificate
//   - The signature certificate needs to be validated against external sources
//   - Multiple certificates might be valid for the same signature
//
// Parameters:
//   - data: The original data that was signed
//   - signature: The signature to verify (certificate will be temporarily replaced)
//   - certificate: The specific certificate to use for verification
//   - opts: Verification options controlling validation behavior
//
// Returns nil if the signature is valid with the provided certificate,
// or an error describing the validation failure.
//
// The function temporarily replaces the certificate in the signature object
// for verification, then restores the original certificate afterward.
//
// Example:
//
//	// Verify signature against a known trusted certificate
//	trustedCert, err := x509.ParseCertificate(knownCertDER)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	err = VerifyWithCertificate(data, signature, trustedCert, DefaultVerifyOptions())
//	if err != nil {
//		log.Printf("Signature verification failed: %v", err)
//		return
//	}
//
//	fmt.Println("Signature verified with trusted certificate")
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

// VerifyDetachedSignature verifies a detached signature.
// Detached signatures contain only the signature bytes without the original
// data or metadata. This function is useful for verifying raw signature bytes
// when you have the certificate and hash algorithm separately.
//
// A detached signature verification requires:
//   - The original signed data
//   - Raw signature bytes
//   - The signer's certificate
//   - The hash algorithm that was used during signing
//
// Parameters:
//   - data: The original data that was signed
//   - signatureData: Signature bytes in raw format (without PKCS#7 container)
//   - certificate: The signer's certificate containing the public key
//   - hashAlgo: The hash algorithm used during signing
//
// Returns nil if the detached signature is valid, or an error if verification fails.
//
// The function automatically detects the signature algorithm from the certificate's
// public key and creates a temporary Signature object for verification.
//
// Example:
//
//	// Read signature from a .sig file
//	sigBytes, err := os.ReadFile("document.pdf.sig")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Load signer certificate
//	cert, err := loadCertificate("signer.crt")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Verify the detached signature
//	err = VerifyDetachedSignature(documentData, sigBytes, cert, crypto.SHA256)
//	if err != nil {
//		log.Printf("Detached signature verification failed: %v", err)
//		return
//	}
//
//	fmt.Println("Detached signature is valid")
func VerifyDetachedSignature(data []byte, signatureData []byte, certificate *x509.Certificate, hashAlgo crypto.Hash) error {
	if certificate == nil {
		return ErrMissingCertificate
	}

	// Determine the algorithm from the public key
	algo, err := GetSignatureAlgorithm(certificate.PublicKey)
	if err != nil {
		return err
	}

	// For detached signatures, verify directly using algorithm-specific functions
	// since signatureData contains raw signature bytes, not PKCS#7 data
	switch algo {
	case AlgorithmRSA:
		// Compute digest for RSA verification
		hasher := hashAlgo.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		return verifyRSASignature(certificate.PublicKey, digest, signatureData, hashAlgo)

	case AlgorithmECDSA:
		// Compute digest for ECDSA verification
		hasher := hashAlgo.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		return verifyECDSASignature(certificate.PublicKey, digest, signatureData, hashAlgo)

	case AlgorithmEd25519:
		// Ed25519 verifies the message directly, not a hash
		return verifyEd25519Signature(certificate.PublicKey, data, signatureData)

	default:
		return fmt.Errorf("unsupported algorithm for detached verification: %s", algo)
	}
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

// ExtractCertificateFromSignature extracts the signer's certificate from a signature.
// This utility function provides safe access to the certificate embedded in a
// signature, with proper error handling for missing certificates.
//
// Parameters:
//   - signature: The signature containing the certificate to extract
//
// Returns the embedded X.509 certificate, or an error if the signature is nil
// or doesn't contain a certificate.
//
// This function is commonly used when you need to examine certificate properties
// or perform additional certificate validation outside of signature verification.
//
// Example:
//
//	cert, err := ExtractCertificateFromSignature(signature)
//	if err != nil {
//		log.Printf("No certificate in signature: %v", err)
//		return
//	}
//
//	fmt.Printf("Signer: %s\n", cert.Subject.CommonName)
//	fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
//	fmt.Printf("Valid until: %s\n", cert.NotAfter.Format(time.RFC3339))
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

// IsSignatureValid performs a quick structural validation of a signature.
// This function checks that the signature has the minimum required fields
// populated, but does not perform cryptographic verification.
//
// Validation checks:
//   - Signature object is not nil
//   - Signature data is not empty
//   - Algorithm is specified
//   - Hash algorithm is specified (not zero value)
//
// Parameters:
//   - signature: The signature structure to validate
//
// Returns true if the signature structure appears valid, false otherwise.
//
// This is a lightweight check useful for early validation before attempting
// cryptographic verification. It helps catch obvious errors without the
// computational cost of actual signature verification.
//
// Example:
//
//	if !IsSignatureValid(signature) {
//		log.Printf("Signature structure is invalid")
//		return
//	}
//
//	// Proceed with cryptographic verification
//	err := VerifySignature(data, signature, opts)
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

// GetSignatureInfo returns human-readable information about a signature.
// This function formats signature metadata into a readable string suitable
// for display, logging, or debugging purposes.
//
// The returned information includes:
//   - Signature algorithm (RSA, ECDSA, Ed25519)
//   - Hash algorithm (SHA256, SHA384, SHA512, etc.)
//   - Signature format (PKCS#7, CMS, etc.)
//   - Signer information from certificate (if available)
//   - Certificate validity period
//   - Timestamp information (if available)
//
// Parameters:
//   - signature: The signature to describe
//
// Returns a multi-line string containing formatted signature information,
// or "No signature" if the signature is nil.
//
// This function is particularly useful for:
//   - Logging signature details for audit trails
//   - Debugging signature verification issues
//   - Displaying signature properties to users
//   - Generating signature reports
//
// Example:
//
//	info := GetSignatureInfo(signature)
//	fmt.Printf("Signature Details:\n%s", info)
//
//	// Example output:
//	// Algorithm: RSA
//	// Hash: SHA256
//	// Format: PKCS7
//	// Signer: John Doe
//	// Issuer: Corporate CA
//	// Valid from: 2024-01-01T00:00:00Z
//	// Valid until: 2025-01-01T00:00:00Z
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

// verifyPKCS7SignatureFormat verifies a PKCS#7 format signature using Smallstep PKCS#7 library
func verifyPKCS7SignatureFormat(data []byte, signature *Signature, opts VerifyOptions) error {
	// Parse the PKCS#7 signature data
	p7, err := pkcs7.Parse(signature.Data)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS#7 signature: %w", err)
	}

	// CRITICAL SECURITY FIX: Always set the content to the provided data
	// This ensures we verify against the actual data being tested, not embedded content
	if signature.Format == FormatPKCS7Detached {
		// For detached signatures, set the content
		p7.Content = data
	} else {
		// For attached signatures, we need to verify that the embedded content
		// matches the provided data to prevent signature substitution attacks
		if len(p7.Content) != len(data) {
			return fmt.Errorf("data length mismatch: provided %d bytes, signature contains %d bytes", len(data), len(p7.Content))
		}
		for i := range data {
			if p7.Content[i] != data[i] {
				return fmt.Errorf("data content mismatch: provided data does not match signed content")
			}
		}
		// Set content to ensure verification uses the provided data
		p7.Content = data
	}

	// CRITICAL SECURITY FIX: Verify against the specific certificate
	// The p7.Verify() call alone doesn't verify the signature was created by the expected certificate
	if signature.Certificate != nil {
		// First do standard PKCS#7 verification
		err = p7.Verify()
		if err != nil {
			return fmt.Errorf("PKCS#7 signature verification failed: %w", err)
		}

		// Then verify the signature was created by the expected certificate
		// Check if the expected certificate is in the PKCS#7 signers
		signerCert := p7.GetOnlySigner()
		if signerCert == nil {
			return fmt.Errorf("PKCS#7 signature does not contain exactly one signer")
		}

		// Compare the certificates by their raw bytes (most reliable method)
		if !signerCert.Equal(signature.Certificate) {
			return fmt.Errorf("signature was not created by the expected certificate")
		}
	} else {
		// Standard PKCS#7 verification when no specific certificate is required
		err = p7.Verify()
		if err != nil {
			return fmt.Errorf("PKCS#7 signature verification failed: %w", err)
		}
	}

	return nil
}

// verifyEd25519PKCS7Signature verifies an Ed25519 PKCS#7 signature using RFC 8419 ASN.1 implementation
func verifyEd25519PKCS7Signature(data []byte, signature *Signature) error {
	// Use RFC 8419 Ed25519 PKCS#7 verification
	info, err := internalcrypto.VerifyEd25519PKCS7Signature(data, signature.Data)
	if err != nil {
		return fmt.Errorf("Ed25519 PKCS#7 verification failed: %w", err)
	}

	if !info.Verified {
		return ErrVerificationFailed
	}

	// Verify the certificate matches (if provided in signature)
	if signature.Certificate != nil {
		if !signature.Certificate.Equal(info.Certificate) {
			return fmt.Errorf("certificate mismatch between signature and PKCS#7 data")
		}
	} else {
		// Populate certificate from PKCS#7 data
		signature.Certificate = info.Certificate
	}

	return nil
}
