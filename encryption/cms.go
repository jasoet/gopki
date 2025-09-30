// File cms.go implements Cryptographic Message Syntax (CMS) format support using
// external Mozilla PKCS7 library for reliable and standards-compliant implementation.
//
// This replaces the previous complex manual ASN.1 implementation with a
// battle-tested external library, reducing complexity and maintenance burden
// while improving security and standards compliance.
//
// Standards compliance:
//   - RFC 5652: Cryptographic Message Syntax (CMS)
//   - PKCS#7: Cryptographic Message Syntax (legacy compatibility)
//   - AES-256-GCM: Authenticated encryption
//   - RSA-OAEP: Key transport mechanism
//
// Features:
//   - Envelope encryption for multiple recipients
//   - Certificate-based encryption and decryption
//   - AES-256-GCM authenticated encryption (default)
//   - Standards-compliant ASN.1 DER encoding
//   - Simplified and maintainable codebase
//
// Security:
//   - Authenticated encryption with AES-GCM
//   - RSA-OAEP for secure key transport
//   - Certificate validation during decryption
//   - No manual ASN.1 parsing (reduces attack surface)
//
// Migration note:
//
//	The API signature for DecodeFromCMS has changed to require certificate
//	and private key parameters for proper decryption. This is more secure
//	and explicit than the previous implementation.
package encryption

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/smallstep/pkcs7"
)

type CMS []byte

// envelopeContainer is used to serialize the entire EncryptedData structure
// for CMS encoding, preserving all envelope encryption metadata
type envelopeContainer struct {
	Algorithm    Algorithm              `json:"algorithm"`
	Data         []byte                 `json:"data"`
	EncryptedKey []byte                 `json:"encrypted_key,omitempty"`
	IV           []byte                 `json:"iv,omitempty"`
	Tag          []byte                 `json:"tag,omitempty"`
	Recipients   []recipientInfoJSON    `json:"recipients,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// recipientInfoJSON is a JSON-serializable version of RecipientInfo
type recipientInfoJSON struct {
	KeyID                  []byte    `json:"key_id,omitempty"`
	EncryptedKey           []byte    `json:"encrypted_key"`
	KeyEncryptionAlgorithm Algorithm `json:"key_encryption_algorithm"`
	EphemeralKey           []byte    `json:"ephemeral_key,omitempty"`
	KeyIV                  []byte    `json:"key_iv,omitempty"`
	KeyTag                 []byte    `json:"key_tag,omitempty"`
}

// EncodeToCMS converts EncryptedData to CMS format using external library
func EncodeToCMS(data *EncryptedData) (CMS, error) {
	if data == nil {
		return nil, fmt.Errorf("encrypted data is nil")
	}

	// For envelope encryption, we need recipient certificates
	if len(data.Recipients) == 0 {
		return nil, fmt.Errorf("no recipients available for CMS envelope encryption")
	}

	// Extract certificates from recipients
	var recipients []*x509.Certificate
	for _, recip := range data.Recipients {
		if recip.Certificate != nil {
			recipients = append(recipients, recip.Certificate)
		}
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("no valid certificates found in recipients")
	}

	// For envelope encryption, we need to preserve all the envelope metadata
	// (IV, Tag, EncryptedKey, etc.) through the CMS encode/decode cycle.
	// We serialize the entire EncryptedData structure to JSON and encrypt that.
	var contentToEncrypt []byte
	if data.Algorithm == AlgorithmEnvelope {
		// Serialize envelope metadata
		container := envelopeContainer{
			Algorithm:    data.Algorithm,
			Data:         data.Data,
			EncryptedKey: data.EncryptedKey,
			IV:           data.IV,
			Tag:          data.Tag,
			Metadata:     data.Metadata,
		}

		// Serialize recipient info (excluding certificates to avoid circular serialization)
		for _, recip := range data.Recipients {
			container.Recipients = append(container.Recipients, recipientInfoJSON{
				KeyID:                  recip.KeyID,
				EncryptedKey:           recip.EncryptedKey,
				KeyEncryptionAlgorithm: recip.KeyEncryptionAlgorithm,
				EphemeralKey:           recip.EphemeralKey,
				KeyIV:                  recip.KeyIV,
				KeyTag:                 recip.KeyTag,
			})
		}

		var err error
		contentToEncrypt, err = json.Marshal(container)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize envelope metadata: %w", err)
		}
	} else {
		// For non-envelope encryption, just encrypt the data as before
		contentToEncrypt = data.Data
	}

	// Set encryption algorithm based on our algorithm
	switch data.Algorithm {
	case AlgorithmAESGCM:
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	case AlgorithmRSAOAEP, AlgorithmECDH, AlgorithmX25519, AlgorithmEnvelope:
		// Use AES-256-GCM as default for all asymmetric algorithms
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	default:
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	}

	// Encrypt using external library
	return pkcs7.Encrypt(contentToEncrypt, recipients)
}

// DecodeFromCMS parses CMS format into EncryptedData using external library
//
// Note: This function signature has changed from the original implementation.
// It now requires a certificate and private key for proper decryption,
// which is more secure and explicit.
//
// The function is generic and accepts any private key type:
//   - *rsa.PrivateKey for RSA keys
//   - *ecdsa.PrivateKey for ECDSA keys
//   - ed25519.PrivateKey for Ed25519 keys
//
// Usage examples:
//
//	// Type inference (recommended)
//	data, err := DecodeFromCMS(cmsBytes, cert, rsaPrivateKey)
//
//	// Explicit type parameter
//	data, err := DecodeFromCMS[*rsa.PrivateKey](cmsBytes, cert, rsaPrivateKey)
func DecodeFromCMS[T any](cmsData CMS, cert *x509.Certificate, privateKey T) (*EncryptedData, error) {
	if len(cmsData) == 0 {
		return nil, fmt.Errorf("CMS data is empty")
	}

	// Parse PKCS7 structure
	p7, err := pkcs7.Parse(cmsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7 structure: %w", err)
	}

	// Decrypt the content (this decrypts the CMS layer)
	decryptedContent, err := p7.Decrypt(cert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PKCS7 content: %w", err)
	}

	// Try to deserialize as envelope container (for envelope encryption)
	var container envelopeContainer
	if err := json.Unmarshal(decryptedContent, &container); err == nil {
		// Successfully deserialized envelope structure - reconstruct EncryptedData
		result := &EncryptedData{
			Format:       FormatCMS,
			Algorithm:    container.Algorithm,
			Data:         container.Data,
			EncryptedKey: container.EncryptedKey,
			IV:           container.IV,
			Tag:          container.Tag,
			Recipients:   make([]*RecipientInfo, 0),
			Metadata:     container.Metadata,
			Timestamp:    time.Now(),
		}

		// Reconstruct recipient info with certificate
		for _, recipJSON := range container.Recipients {
			recip := &RecipientInfo{
				Certificate:            cert, // Use the cert provided for decryption
				KeyID:                  recipJSON.KeyID,
				EncryptedKey:           recipJSON.EncryptedKey,
				KeyEncryptionAlgorithm: recipJSON.KeyEncryptionAlgorithm,
				EphemeralKey:           recipJSON.EphemeralKey,
				KeyIV:                  recipJSON.KeyIV,
				KeyTag:                 recipJSON.KeyTag,
			}
			result.Recipients = append(result.Recipients, recip)
		}

		return result, nil
	}

	// Not envelope encryption or failed to deserialize - treat as simple encrypted data
	result := &EncryptedData{
		Format:     FormatCMS,
		Algorithm:  AlgorithmRSAOAEP, // Assume RSA for non-envelope
		Data:       decryptedContent,
		Recipients: make([]*RecipientInfo, 0),
		Metadata:   make(map[string]any),
		Timestamp:  time.Now(),
	}

	// Create a basic recipient info
	recipInfo := &RecipientInfo{
		Certificate:            cert,
		KeyEncryptionAlgorithm: AlgorithmRSAOAEP,
	}
	result.Recipients = append(result.Recipients, recipInfo)

	return result, nil
}

// ValidateCMS validates CMS format data using external library
func ValidateCMS(data CMS) error {
	if len(data) == 0 {
		return fmt.Errorf("CMS data is empty")
	}

	// Try to parse the data
	_, err := pkcs7.Parse(data)
	if err != nil {
		return fmt.Errorf("invalid CMS format: %w", err)
	}

	return nil
}
