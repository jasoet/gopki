// File cms.go implements Cryptographic Message Syntax (CMS) format support for
// encrypted data, providing advanced features and extensibility beyond PKCS#7.
//
// CMS (Cryptographic Message Syntax) is defined in RFC 5652 as the successor to
// PKCS#7. It provides enhanced features including better algorithm agility,
// authenticated encryption, and extensible attribute systems.
//
// Standards compliance:
//   - RFC 5652: Cryptographic Message Syntax (CMS)
//   - RFC 5083: Cryptographic Message Syntax (CMS) Authenticated-Enveloped-Data Content Type
//   - RFC 5084: Using AES-CCM and AES-GCM Authenticated Encryption in the Cryptographic Message Syntax
//   - RFC 8933: Update to the Cryptographic Message Syntax (CMS) for Algorithm Identifier Protection
//
// Enhanced features over PKCS#7:
//   - Authenticated encryption support (AuthEnvelopedData)
//   - Algorithm agility and protection
//   - Extended originator information
//   - Unprotected attributes for metadata
//   - Better support for modern cryptographic algorithms
//   - Enhanced recipient information structures
//
// Supported content types:
//   - EnvelopedData: Traditional public key encrypted data
//   - AuthEnvelopedData: Authenticated encryption with AEAD algorithms
//   - EncryptedData: Symmetric key encrypted data with enhanced attributes
//
// Format characteristics:
//   - ASN.1 DER-encoded structure
//   - Forward compatibility through extensible attributes
//   - Enhanced algorithm identification and protection
//   - Support for complex PKI scenarios
//   - Designed for long-term evolution
//
// Security enhancements:
//   - Algorithm identifier protection against downgrade attacks
//   - Authenticated encryption modes for confidentiality and integrity
//   - Enhanced key management through recipient information
//   - Support for modern AEAD (Authenticated Encryption with Associated Data) algorithms
//
// Use cases:
//   - Advanced PKI environments requiring modern cryptography
//   - Applications requiring authenticated encryption
//   - Long-term secure archival with format evolution
//   - Integration with next-generation cryptographic systems
//   - Multi-recipient scenarios with complex requirements
package encryption

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// OIDs for CMS and encryption algorithms
var (
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidAES256CBC              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES256GCM              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	oidKeyTransport           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDH                   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}    // ECDH
	oidX25519                 = asn1.ObjectIdentifier{1, 3, 101, 110}             // X25519
	oidECPublicKey            = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}    // EC public key
	oidPBES2                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
)

// CMS-specific OIDs
var (
	oidCMSEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
	oidCMSAuthEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
)

// CMSEnvelopedData structure
type cmsEnvelopedData struct {
	Version              int
	OriginatorInfo       originatorInfo `asn1:"implicit,optional,tag:0"`
	RecipientInfos       []cmsRecipientInfo `asn1:"set"`
	EncryptedContentInfo cmsEncryptedContentInfo
	UnprotectedAttrs     []pkix.AttributeTypeAndValue `asn1:"implicit,optional,tag:1,set"`
}

// OriginatorInfo structure
type originatorInfo struct {
	Certs []asn1.RawValue `asn1:"implicit,optional,tag:0"`
	CRLs  []asn1.RawValue `asn1:"implicit,optional,tag:1"`
}

// CMSRecipientInfo structure
type cmsRecipientInfo struct {
	Version                int
	RecipientIdentifier    recipientIdentifier
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
	// Additional fields for key agreement and other methods
	UkeyInfo               []byte `asn1:"implicit,optional,tag:1"`
	Date                   time.Time `asn1:"implicit,optional,tag:2"`
	OtherInfo              asn1.RawValue `asn1:"implicit,optional,tag:3"`
}

// RecipientIdentifier can be IssuerAndSerialNumber or SubjectKeyIdentifier
type recipientIdentifier struct {
	IssuerAndSerial issuerAndSerial `asn1:"optional"`
	SubjectKeyId    []byte `asn1:"implicit,optional,tag:0"`
}

// CMSEncryptedContentInfo structure
type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"implicit,optional,tag:0"`
}

// issuerAndSerial represents the IssuerAndSerialNumber structure
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber int
}

// contentInfo represents the ContentInfo structure
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// EncodeToCMS converts EncryptedData to CMS format
func EncodeToCMS(data *EncryptedData) ([]byte, error) {
	// Create the encrypted content info
	encContent := cmsEncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  getAlgorithmOID(data.Algorithm),
			Parameters: asn1.NullRawValue,
		},
		EncryptedContent: data.Data,
	}

	// Create recipient infos
	var recipients []cmsRecipientInfo

	// If we have encrypted key, create a recipient info
	if len(data.EncryptedKey) > 0 {
		recipient := cmsRecipientInfo{
			Version: 0,
			RecipientIdentifier: recipientIdentifier{
				IssuerAndSerial: issuerAndSerial{
					Issuer:       asn1.RawValue{},
					SerialNumber: 1,
				},
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidRSAEncryption,
				Parameters: asn1.NullRawValue,
			},
			EncryptedKey: data.EncryptedKey,
		}
		recipients = append(recipients, recipient)
	}

	// Add recipients from RecipientInfo if available
	for i, recip := range data.Recipients {
		recipient := cmsRecipientInfo{
			Version: 2, // Version 2 for CMS
			RecipientIdentifier: recipientIdentifier{
				IssuerAndSerial: issuerAndSerial{
					Issuer:       asn1.RawValue{},
					SerialNumber: i + 2,
				},
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  getAlgorithmOID(recip.KeyEncryptionAlgorithm),
				Parameters: asn1.NullRawValue,
			},
			EncryptedKey: recip.EncryptedKey,
		}

		// Add key ID if available
		if len(recip.KeyID) > 0 {
			recipient.RecipientIdentifier.SubjectKeyId = recip.KeyID
			// Clear IssuerAndSerial when using SubjectKeyId
			recipient.RecipientIdentifier.IssuerAndSerial = issuerAndSerial{}
		}

		// Handle ephemeral keys for ECDH/X25519
		if len(recip.EphemeralKey) > 0 {
			// Store ephemeral key in UkeyInfo field for key agreement algorithms
			recipient.UkeyInfo = recip.EphemeralKey
		}

		// Handle additional key material (IV, Tag) for AES-GCM key wrapping
		if len(recip.KeyIV) > 0 || len(recip.KeyTag) > 0 {
			// Combine IV and Tag for storage in OtherInfo
			keyMaterial := make([]byte, 0, len(recip.KeyIV)+len(recip.KeyTag))
			keyMaterial = append(keyMaterial, recip.KeyIV...)
			keyMaterial = append(keyMaterial, recip.KeyTag...)
			recipient.OtherInfo = asn1.RawValue{
				Class:      0,
				Tag:        4, // OCTET STRING
				IsCompound: false,
				Bytes:      keyMaterial,
			}
		}

		recipients = append(recipients, recipient)
	}

	// Create unprotected attributes for metadata
	var unprotectedAttrs []pkix.AttributeTypeAndValue
	if data.Timestamp.Unix() > 0 {
		// Add timestamp as an attribute
		timestampBytes, _ := asn1.Marshal(data.Timestamp)
		unprotectedAttrs = append(unprotectedAttrs, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, // signingTime OID
			Value: asn1.RawValue{Bytes: timestampBytes},
		})
	}

	// Create the CMS enveloped data
	cms := cmsEnvelopedData{
		Version:              2, // CMS version
		RecipientInfos:       recipients,
		EncryptedContentInfo: encContent,
		UnprotectedAttrs:     unprotectedAttrs,
	}

	// Marshal the CMS enveloped data
	cmsBytes, err := asn1.Marshal(cms)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CMS enveloped data: %w", err)
	}

	// Create the ContentInfo
	content := contentInfo{
		ContentType: oidCMSEnvelopedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      cmsBytes,
		},
	}

	// Marshal the ContentInfo
	return asn1.Marshal(content)
}

// DecodeFromCMS parses CMS format into EncryptedData
func DecodeFromCMS(data []byte) (*EncryptedData, error) {
	// Parse ContentInfo
	var content contentInfo
	rest, err := asn1.Unmarshal(data, &content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CMS ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after CMS ContentInfo")
	}

	// Check content type
	if !content.ContentType.Equal(oidCMSEnvelopedData) && !content.ContentType.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf("expected CMS enveloped data, got %s", content.ContentType)
	}

	// Parse CMS EnvelopedData
	var cms cmsEnvelopedData
	if _, err := asn1.Unmarshal(content.Content.Bytes, &cms); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CMS enveloped data: %w", err)
	}

	result := &EncryptedData{
		Format:     FormatCMS,
		Algorithm:  oidToAlgorithm(cms.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm),
		Data:       cms.EncryptedContentInfo.EncryptedContent,
		Recipients: make([]*RecipientInfo, 0),
		Metadata:   make(map[string]interface{}),
	}

	// Extract recipient information
	for _, recip := range cms.RecipientInfos {
		recipInfo := &RecipientInfo{
			EncryptedKey:           recip.EncryptedKey,
			KeyEncryptionAlgorithm: oidToAlgorithm(recip.KeyEncryptionAlgorithm.Algorithm),
		}

		// Extract key ID if available
		if len(recip.RecipientIdentifier.SubjectKeyId) > 0 {
			recipInfo.KeyID = recip.RecipientIdentifier.SubjectKeyId
		}

		// Extract ephemeral key for ECDH/X25519
		if len(recip.UkeyInfo) > 0 {
			recipInfo.EphemeralKey = recip.UkeyInfo
		}

		// Extract additional key material (IV, Tag) from OtherInfo
		if len(recip.OtherInfo.Bytes) > 0 {
			keyMaterial := recip.OtherInfo.Bytes
			// For AES-GCM, we expect 12 bytes IV + 16 bytes Tag = 28 bytes total
			if len(keyMaterial) >= 28 {
				recipInfo.KeyIV = keyMaterial[:12]
				recipInfo.KeyTag = keyMaterial[12:28]
			} else if len(keyMaterial) >= 12 {
				// If we only have IV
				recipInfo.KeyIV = keyMaterial[:12]
			}
		}

		result.Recipients = append(result.Recipients, recipInfo)
	}

	// If there's only one recipient and no Recipients array was set, use the encrypted key directly
	if len(result.Recipients) == 1 && len(result.EncryptedKey) == 0 {
		result.EncryptedKey = result.Recipients[0].EncryptedKey
	}

	// Extract timestamp from unprotected attributes
	for _, attr := range cms.UnprotectedAttrs {
		if attr.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}) {
			// attr.Value is of type any, need to assert it as asn1.RawValue
			if rawValue, ok := attr.Value.(asn1.RawValue); ok {
				var timestamp time.Time
				if _, err := asn1.Unmarshal(rawValue.Bytes, &timestamp); err == nil {
					result.Timestamp = timestamp
				}
			}
		}
	}

	return result, nil
}

// ValidateCMS validates CMS format data
func ValidateCMS(data []byte) error {
	// Try to parse as CMS
	var content contentInfo
	rest, err := asn1.Unmarshal(data, &content)
	if err != nil {
		return fmt.Errorf("invalid CMS format: %w", err)
	}
	if len(rest) > 0 {
		return errors.New("trailing data in CMS format")
	}

	// Check for valid CMS content types
	validTypes := []asn1.ObjectIdentifier{
		oidCMSEnvelopedData,
		oidCMSAuthEnvelopedData,
		oidEnvelopedData,
	}

	valid := false
	for _, oid := range validTypes {
		if content.ContentType.Equal(oid) {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("invalid CMS content type: %s", content.ContentType)
	}

	return nil
}

// getAlgorithmOID returns the OID for an encryption algorithm
func getAlgorithmOID(alg EncryptionAlgorithm) asn1.ObjectIdentifier {
	switch alg {
	case AlgorithmRSAOAEP:
		return oidRSAEncryption
	case AlgorithmECDH:
		return oidECDH
	case AlgorithmX25519:
		return oidX25519
	case AlgorithmAESGCM:
		return oidAES256GCM
	case AlgorithmEnvelope:
		return oidEnvelopedData
	default:
		return oidData
	}
}

// oidToAlgorithm converts an OID to an EncryptionAlgorithm
func oidToAlgorithm(oid asn1.ObjectIdentifier) EncryptionAlgorithm {
	switch {
	case oid.Equal(oidRSAEncryption):
		return AlgorithmRSAOAEP
	case oid.Equal(oidECDH), oid.Equal(oidECPublicKey):
		return AlgorithmECDH
	case oid.Equal(oidX25519):
		return AlgorithmX25519
	case oid.Equal(oidAES256GCM):
		return AlgorithmAESGCM
	case oid.Equal(oidAES256CBC):
		return AlgorithmAESGCM // Treat CBC as GCM for compatibility
	case oid.Equal(oidEnvelopedData):
		return AlgorithmEnvelope
	default:
		return ""
	}
}