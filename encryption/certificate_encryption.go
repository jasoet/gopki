// File certificate_encryption.go provides certificate-based encryption operations
// that integrate with the GoPKI certificate infrastructure for document-level encryption.
//
// This file implements high-level encryption operations that work directly with
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
package encryption

import (
	"fmt"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
)

// CertificateEncryptor provides certificate-based encryption operations that integrate
// with the GoPKI certificate infrastructure for high-level document encryption.
//
// This encryptor simplifies PKI-based encryption workflows by:
//   - Accepting X.509 certificates directly (no need to extract public keys)
//   - Automatically validating certificate properties
//   - Using envelope encryption for optimal performance
//   - Supporting all certificate key types (RSA, ECDSA, Ed25519)
//   - Integrating with certificate-based access control systems
//
// The encryptor uses envelope encryption internally to provide:
//   - Efficient encryption for any data size
//   - Consistent performance regardless of certificate key type
//   - Support for future multi-recipient encryption
//
// Typical workflow:
//   1. Load recipient certificate from file, store, or network
//   2. Optionally validate certificate (expiration, revocation, chain)
//   3. Encrypt data using the certificate
//   4. Store or transmit the encrypted data
//   5. Recipient decrypts using their private key
type CertificateEncryptor struct {
	envelope *EnvelopeEncryptor
}

// NewCertificateEncryptor creates a new certificate-based encryptor instance.
//
// The encryptor is initialized with an envelope encryptor to handle the
// underlying hybrid encryption operations efficiently.
//
// Returns:
//   - *CertificateEncryptor: A new encryptor ready for certificate-based operations
//
// Example:
//
//	encryptor := NewCertificateEncryptor()
//	cert, _ := cert.LoadCertificateFromFile("recipient.pem")
//	encrypted, err := encryptor.EncryptDocument(data, cert, opts)
func NewCertificateEncryptor() *CertificateEncryptor {
	return &CertificateEncryptor{
		envelope: NewEnvelopeEncryptor(),
	}
}

// EncryptDocument encrypts a document using a certificate's public key for
// certificate-based encryption workflows.
//
// This method provides a high-level interface for encrypting data to a specific
// certificate holder. It extracts the public key from the certificate and uses
// envelope encryption for optimal performance and security.
//
// The method automatically:
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
//   - *EncryptedData: Encrypted document with certificate-based metadata
//   - error: Certificate validation errors or encryption failures
//
// Security considerations:
//   - Certificate should be validated before encryption (expiration, revocation)
//   - Certificate key usage should allow encryption operations
//   - Certificate chain validation may be required in enterprise environments
//   - Consider checking certificate revocation status for high-security applications
//
// Example usage:
//
//	// Load recipient certificate
//	cert, err := cert.LoadCertificateFromFile("alice@example.com.pem")
//	if err != nil {
//		log.Fatal("Failed to load certificate:", err)
//	}
//
//	// Optional: Verify certificate is still valid
//	if time.Now().After(cert.Certificate.NotAfter) {
//		log.Fatal("Certificate has expired")
//	}
//
//	// Encrypt document for the certificate holder
//	encryptor := NewCertificateEncryptor()
//	document := []byte("confidential business document")
//
//	encrypted, err := encryptor.EncryptDocument(document, cert, DefaultEncryptOptions())
//	if err != nil {
//		log.Fatal("Document encryption failed:", err)
//	}
//
//	// The encrypted document can only be decrypted by the certificate holder's private key
func (e *CertificateEncryptor) EncryptDocument(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Extract public key from certificate
	publicKey := certificate.Certificate.PublicKey

	// Use envelope encryption for hybrid approach
	encryptedData, err := e.envelope.EncryptForPublicKey(data, publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt document: %w", err)
	}

	// Add certificate information to recipients
	if opts.IncludeCertificate {
		recipientInfo := &RecipientInfo{
			Certificate:            certificate.Certificate,
			EncryptedKey:           encryptedData.EncryptedKey,
			KeyEncryptionAlgorithm: GetAlgorithmForKeyType(getCertificateKeyType(certificate)),
		}
		encryptedData.Recipients = []*RecipientInfo{recipientInfo}
	}

	return encryptedData, nil
}

// DecryptDocument decrypts a document using a certificate and its corresponding private key
func (e *CertificateEncryptor) DecryptDocument(encrypted *EncryptedData, keyPair any, opts DecryptOptions) ([]byte, error) {
	if encrypted == nil {
		return nil, fmt.Errorf("encrypted data is required")
	}

	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	// Use envelope decryption
	plaintext, err := e.envelope.Decrypt(encrypted, keyPair, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt document: %w", err)
	}

	return plaintext, nil
}

// EncryptForMultipleCertificates encrypts data for multiple certificate holders
func (e *CertificateEncryptor) EncryptForMultipleCertificates(data []byte, certificates []*cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	if len(certificates) == 0 {
		return nil, fmt.Errorf("at least one certificate is required")
	}

	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Extract public keys from certificates
	publicKeys := make([]any, len(certificates))
	for i, certificate := range certificates {
		if certificate == nil {
			return nil, fmt.Errorf("certificate %d is nil", i)
		}
		publicKeys[i] = certificate.Certificate.PublicKey
	}

	// Use envelope encryption for multiple recipients
	encryptedData, err := e.envelope.EncryptForMultipleRecipients(data, publicKeys, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt for multiple certificates: %w", err)
	}

	// Add certificate information to recipients if requested
	if opts.IncludeCertificate && len(encryptedData.Recipients) == len(certificates) {
		for i, certificate := range certificates {
			if i < len(encryptedData.Recipients) {
				encryptedData.Recipients[i].Certificate = certificate.Certificate
			}
		}
	}

	return encryptedData, nil
}

// DecryptForCertificateHolder decrypts multi-recipient data for a specific certificate holder
func (e *CertificateEncryptor) DecryptForCertificateHolder(encrypted *EncryptedData, keyPair any, recipientIndex int, opts DecryptOptions) ([]byte, error) {
	if encrypted == nil {
		return nil, fmt.Errorf("encrypted data is required")
	}

	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	// Use envelope decryption for specific recipient
	plaintext, err := e.envelope.DecryptForRecipient(encrypted, keyPair, recipientIndex, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt for certificate holder %d: %w", recipientIndex, err)
	}

	return plaintext, nil
}

// EncryptWithKeyUsageValidation encrypts data after validating certificate key usage
func (e *CertificateEncryptor) EncryptWithKeyUsageValidation(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
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

	return e.EncryptDocument(data, certificate, opts)
}

// DecryptWithCertificateValidation decrypts data after validating certificate
func (e *CertificateEncryptor) DecryptWithCertificateValidation(encrypted *EncryptedData, keyPair any, certificate *cert.Certificate, opts DecryptOptions) ([]byte, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	// Validate certificate is suitable for decryption
	if err := validateCertificateForDecryption(certificate); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Check certificate validity unless explicitly disabled
	if !opts.SkipExpirationCheck {
		verifyTime := opts.VerifyTime
		if verifyTime.IsZero() {
			verifyTime = time.Now()
		}

		if verifyTime.Before(certificate.Certificate.NotBefore) {
			return nil, ErrCertificateNotYetValid
		}
		if verifyTime.After(certificate.Certificate.NotAfter) {
			return nil, ErrCertificateExpired
		}
	}

	return e.DecryptDocument(encrypted, keyPair, opts)
}

// FindRecipientByCertificate finds the recipient index for a specific certificate
func (e *CertificateEncryptor) FindRecipientByCertificate(encrypted *EncryptedData, targetCertificate *cert.Certificate) (int, error) {
	if encrypted == nil {
		return -1, fmt.Errorf("encrypted data is required")
	}
	if targetCertificate == nil {
		return -1, fmt.Errorf("target certificate is required")
	}

	for i, recipient := range encrypted.Recipients {
		if recipient.Certificate != nil {
			// Compare certificate fingerprints or subjects
			if recipient.Certificate.Equal(targetCertificate.Certificate) {
				return i, nil
			}
		}
	}

	return -1, fmt.Errorf("certificate not found in recipients")
}

// SupportedAlgorithms returns the algorithms supported by the certificate encryptor
func (e *CertificateEncryptor) SupportedAlgorithms() []EncryptionAlgorithm {
	return e.envelope.SupportedAlgorithms()
}

// Type-safe wrapper methods using generic constraints

// DecryptDocumentTyped provides type-safe document decryption using generic constraints
func DecryptDocumentTyped[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, opts DecryptOptions) ([]byte, error) {
	encryptor := NewCertificateEncryptor()
	return encryptor.DecryptDocument(encrypted, keyPair, opts)
}

// DecryptForCertificateHolderTyped provides type-safe multi-recipient decryption using generic constraints
func DecryptForCertificateHolderTyped[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, recipientIndex int, opts DecryptOptions) ([]byte, error) {
	encryptor := NewCertificateEncryptor()
	return encryptor.DecryptForCertificateHolder(encrypted, keyPair, recipientIndex, opts)
}

// DecryptWithCertificateValidationTyped provides type-safe certificate validation during decryption
func DecryptWithCertificateValidationTyped[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, certificate *cert.Certificate, opts DecryptOptions) ([]byte, error) {
	encryptor := NewCertificateEncryptor()
	return encryptor.DecryptWithCertificateValidation(encrypted, keyPair, certificate, opts)
}

// Helper functions

func getCertificateKeyType(certificate *cert.Certificate) string {
	publicKey := certificate.Certificate.PublicKey
	return getPublicKeyType(publicKey)
}

func validateCertificateForEncryption(certificate *cert.Certificate) error {
	// Check key usage for encryption
	keyUsage := certificate.Certificate.KeyUsage
	if keyUsage&(1<<2) == 0 && keyUsage&(1<<4) == 0 { // KeyEncipherment or DataEncipherment
		return fmt.Errorf("certificate does not have encryption key usage")
	}

	return nil
}

func validateCertificateForDecryption(certificate *cert.Certificate) error {
	// Check key usage for decryption
	keyUsage := certificate.Certificate.KeyUsage
	if keyUsage&(1<<2) == 0 && keyUsage&(1<<4) == 0 { // KeyEncipherment or DataEncipherment
		return fmt.Errorf("certificate does not have decryption key usage")
	}

	return nil
}

// Common errors for certificate encryption
var (
	ErrCertificateExpired     = fmt.Errorf("certificate has expired")
	ErrCertificateNotYetValid = fmt.Errorf("certificate is not yet valid")
	ErrInvalidKeyUsage        = fmt.Errorf("certificate has invalid key usage for encryption")
)
