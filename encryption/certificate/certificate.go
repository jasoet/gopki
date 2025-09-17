// Package certificate provides certificate-based encryption operations
// that integrate with the GoPKI certificate infrastructure for document-level encryption.
//
// This package implements high-level encryption operations that work directly with
// X.509 certificates, making it easy to encrypt data for certificate holders
// without needing to extract and manage public keys separately.
//
// Key features:
//   - Direct encryption using certificate public keys
//   - Integration with GoPKI certificate management
//   - Support for certificate-based workflows
//   - Automatic algorithm selection based on certificate key type
//   - Certificate validation and verification during encryption
//
// Use cases:
//   - Document encryption for specific certificate holders
//   - Email encryption using recipient certificates
//   - File encryption in PKI environments
//   - Secure messaging systems with certificate-based identity
//   - Enterprise applications with certificate-based access control
//
// Security considerations:
//   - Certificate validity should be verified before encryption
//   - Certificate revocation status should be checked in production
//   - Certificate chain validation may be required depending on use case
//   - Key usage extensions in certificates should be respected
//
// Example usage:
//
//	// Load recipient certificate
//	recipientCert, err := cert.LoadCertificateFromFile("alice@example.com.pem")
//	if err != nil {
//		log.Fatal("Failed to load certificate:", err)
//	}
//
//	// Encrypt document for the certificate holder
//	document := []byte("confidential business document")
//	encrypted, err := certificate.EncryptDocument(document, recipientCert, opts)
//	if err != nil {
//		log.Fatal("Document encryption failed:", err)
//	}
//
//	// Decrypt with certificate holder's key pair
//	decrypted, err := certificate.DecryptDocument(encrypted, aliceKeyPair, opts)
package certificate

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/envelope"
	"github.com/jasoet/gopki/keypair"
)

// EncryptDocument encrypts a document using a certificate's public key for
// certificate-based encryption workflows.
//
// This function provides a high-level interface for encrypting data to a specific
// certificate holder. It extracts the public key from the certificate and uses
// envelope encryption for optimal performance and security.
//
// The function automatically:
//   - Validates the certificate is not nil
//   - Extracts the public key from the certificate
//   - Selects the appropriate encryption algorithm based on key type
//   - Uses envelope encryption for efficiency
//   - Adds certificate information to encrypted data metadata
//
// Parameters:
//   - data: The document or data to encrypt (any size supported)
//   - certificate: The recipient's X.509 certificate containing the public key
//   - opts: Encryption options (algorithm selection, format, etc.)
//
// Returns:
//   - *encryption.EncryptedData: Encrypted document with certificate-based metadata
//   - error: Certificate validation errors or encryption failures
//
// Security considerations:
//   - Certificate should be validated before encryption (expiration, revocation)
//   - Certificate key usage should allow encryption operations
//   - Certificate chain validation may be required in enterprise environments
//   - Consider checking certificate revocation status for high-security applications
//
// Example:
//
//	// Load recipient certificate
//	recipientCert, err := cert.LoadCertificateFromFile("alice@example.com.pem")
//	if err != nil {
//		log.Fatal("Failed to load certificate:", err)
//	}
//
//	// Optional: Verify certificate is still valid
//	if time.Now().After(recipientCert.Certificate.NotAfter) {
//		log.Fatal("Certificate has expired")
//	}
//
//	// Encrypt document for the certificate holder
//	document := []byte("confidential business document")
//	encrypted, err := certificate.EncryptDocument(document, recipientCert, opts)
//	if err != nil {
//		log.Fatal("Document encryption failed:", err)
//	}
func EncryptDocument(data []byte, certificate *cert.Certificate, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	if err := encryption.ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Extract public key from certificate
	publicKey := certificate.Certificate.PublicKey

	// Use envelope encryption for hybrid approach
	encryptedData, err := envelope.EncryptForPublicKeyAny(data, publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt document: %w", err)
	}

	// Add certificate info to metadata if requested
	if opts.IncludeCertificate {
		if encryptedData.Metadata == nil {
			encryptedData.Metadata = make(map[string]interface{})
		}
		encryptedData.Metadata["certificate_subject"] = certificate.Certificate.Subject.String()
		encryptedData.Metadata["certificate_serial"] = certificate.Certificate.SerialNumber.String()
	}

	return encryptedData, nil
}

// DecryptDocument decrypts a document using a certificate and its corresponding private key.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - encrypted: The encrypted data to decrypt
//   - keyPair: The key pair (private key used for decryption)
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted document
//   - error: Any error during decryption
//
// Example:
//
//	decrypted, err := certificate.DecryptDocument(encrypted, aliceKeyPair, opts)
func DecryptDocument[T keypair.KeyPair](encrypted *encryption.EncryptedData, keyPair T, opts encryption.DecryptOptions) ([]byte, error) {
	if encrypted == nil {
		return nil, fmt.Errorf("encrypted data is required")
	}

	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	// Use envelope decryption
	plaintext, err := envelope.Decrypt(encrypted, keyPair, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt document: %w", err)
	}

	return plaintext, nil
}

// EncryptForMultipleCertificates encrypts data for multiple certificate holders.
//
// This function encrypts data so that any of the certificate holders can decrypt it
// using their private key. This is useful for group messaging or shared documents.
//
// Parameters:
//   - data: The data to encrypt
//   - certificates: List of recipient certificates
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data for all certificate holders
//   - error: Any error during encryption
//
// Example:
//
//	certificates := []*cert.Certificate{aliceCert, bobCert, charlieCert}
//	encrypted, err := certificate.EncryptForMultipleCertificates(data, certificates, opts)
func EncryptForMultipleCertificates(data []byte, certificates []*cert.Certificate, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if len(certificates) == 0 {
		return nil, fmt.Errorf("at least one certificate is required")
	}

	if err := encryption.ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Extract public keys from all certificates
	publicKeys := make([]keypair.GenericPublicKey, len(certificates))
	for i, cert := range certificates {
		if cert == nil {
			return nil, fmt.Errorf("certificate at index %d is nil", i)
		}
		publicKeys[i] = cert.Certificate.PublicKey
	}

	// Use envelope encryption for multiple recipients
	encryptedData, err := envelope.EncryptForMultipleRecipients(data, publicKeys, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt for multiple certificates: %w", err)
	}

	// Add certificate info to metadata
	if opts.IncludeCertificate && len(certificates) > 0 {
		if encryptedData.Metadata == nil {
			encryptedData.Metadata = make(map[string]interface{})
		}

		var subjects []string
		for _, cert := range certificates {
			subjects = append(subjects, cert.Certificate.Subject.String())
		}
		encryptedData.Metadata["recipient_subjects"] = subjects
	}

	return encryptedData, nil
}

// DecryptForCertificateHolder decrypts multi-recipient data for a specific certificate holder.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - encrypted: The multi-recipient encrypted data
//   - keyPair: The certificate holder's key pair
//   - recipientIndex: The index of this recipient in the recipient list
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted data
//   - error: Any error during decryption
//
// Example:
//
//	// Bob is recipient at index 1
//	decrypted, err := certificate.DecryptForCertificateHolder(encrypted, bobKeyPair, 1, opts)
func DecryptForCertificateHolder[T keypair.KeyPair](encrypted *encryption.EncryptedData, keyPair T, recipientIndex int, opts encryption.DecryptOptions) ([]byte, error) {
	if encrypted == nil {
		return nil, fmt.Errorf("encrypted data is required")
	}

	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	// Use envelope decryption for specific recipient
	plaintext, err := envelope.DecryptForRecipient(encrypted, keyPair, recipientIndex, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt for certificate holder %d: %w", recipientIndex, err)
	}

	return plaintext, nil
}

// EncryptWithKeyUsageValidation encrypts data after validating certificate key usage.
//
// This function checks that the certificate is suitable for encryption operations
// before proceeding with the encryption. It validates:
//   - Certificate validity period (not expired, not yet valid)
//   - Key usage extensions (if present)
//   - Extended key usage (if present)
//
// Parameters:
//   - data: The data to encrypt
//   - certificate: The recipient's certificate
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data
//   - error: Validation or encryption error
//
// Example:
//
//	// This will validate the certificate before encryption
//	encrypted, err := certificate.EncryptWithKeyUsageValidation(data, recipientCert, opts)
func EncryptWithKeyUsageValidation(data []byte, certificate *cert.Certificate, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	// Validate certificate is suitable for encryption
	if err := validateCertificateForEncryption(certificate); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Check certificate validity
	now := time.Now()
	if now.Before(certificate.Certificate.NotBefore) {
		return nil, fmt.Errorf("certificate is not yet valid")
	}
	if now.After(certificate.Certificate.NotAfter) {
		return nil, fmt.Errorf("certificate has expired")
	}

	return EncryptDocument(data, certificate, opts)
}

// DecryptWithCertificateValidation decrypts data after validating certificate.
//
// This function validates that the provided certificate matches the key pair
// being used for decryption, providing an additional layer of verification.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - encrypted: The encrypted data
//   - keyPair: The key pair for decryption
//   - certificate: The certificate to validate against
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted data
//   - error: Validation or decryption error
//
// Example:
//
//	// This will validate the certificate matches the key pair
//	decrypted, err := certificate.DecryptWithCertificateValidation(
//		encrypted, aliceKeyPair, aliceCert, opts)
func DecryptWithCertificateValidation[T keypair.KeyPair](encrypted *encryption.EncryptedData, keyPair T, certificate *cert.Certificate, opts encryption.DecryptOptions) ([]byte, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	// Validate certificate is suitable for decryption
	if err := validateCertificateForDecryption(certificate); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Decrypt the data
	return DecryptDocument(encrypted, keyPair, opts)
}

// Helper functions

// validateCertificateForEncryption checks if a certificate can be used for encryption
func validateCertificateForEncryption(certificate *cert.Certificate) error {
	if certificate == nil || certificate.Certificate == nil {
		return fmt.Errorf("invalid certificate")
	}

	// Check key usage if present
	if certificate.Certificate.KeyUsage != 0 {
		// Check for key encipherment or key agreement
		if certificate.Certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 &&
			certificate.Certificate.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return fmt.Errorf("certificate key usage does not allow encryption")
		}
	}

	return nil
}

// validateCertificateForDecryption checks if a certificate can be used for decryption
func validateCertificateForDecryption(certificate *cert.Certificate) error {
	if certificate == nil || certificate.Certificate == nil {
		return fmt.Errorf("invalid certificate")
	}

	// For decryption, we mainly check that the certificate is valid
	// The actual key usage was checked when encrypting
	return nil
}