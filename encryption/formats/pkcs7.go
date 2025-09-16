package formats

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/jasoet/gopki/encryption"
)

// PKCS7Format handles PKCS#7/CMS format for encrypted data
type PKCS7Format struct{}

// NewPKCS7Format creates a new PKCS#7 format handler
func NewPKCS7Format() *PKCS7Format {
	return &PKCS7Format{}
}

// Name returns the format name
func (f *PKCS7Format) Name() string {
	return string(encryption.FormatPKCS7)
}

// OIDs for PKCS#7
var (
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidAES256CBC              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidKeyTransport           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPBES2                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
)

// PKCS#7 ContentInfo structure
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// EnvelopedData structure for PKCS#7
type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

// RecipientInfo structure
type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// IssuerAndSerialNumber structure
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber int
}

// EncryptedContentInfo structure
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"implicit,optional,tag:0"`
}

// Encode converts EncryptedData to PKCS#7 format
func (f *PKCS7Format) Encode(data *encryption.EncryptedData) ([]byte, error) {
	// Create the encrypted content info
	encContent := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  getAlgorithmOID(data.Algorithm),
			Parameters: asn1.NullRawValue,
		},
	}

	// Set the encrypted content
	if len(data.Data) > 0 {
		encContent.EncryptedContent = asn1.RawValue{
			Class:      2, // context-specific
			Tag:        0,
			IsCompound: false,
			Bytes:      data.Data,
		}
	}

	// Create recipient infos
	var recipients []recipientInfo

	// If we have encrypted key, create a recipient info
	if len(data.EncryptedKey) > 0 {
		recipient := recipientInfo{
			Version: 0,
			IssuerAndSerialNumber: issuerAndSerial{
				Issuer:       asn1.RawValue{},
				SerialNumber: 1,
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
		recipient := recipientInfo{
			Version: 0,
			IssuerAndSerialNumber: issuerAndSerial{
				Issuer:       asn1.RawValue{},
				SerialNumber: i + 2,
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  getAlgorithmOID(recip.KeyEncryptionAlgorithm),
				Parameters: asn1.NullRawValue,
			},
			EncryptedKey: recip.EncryptedKey,
		}
		recipients = append(recipients, recipient)
	}

	// Create the enveloped data
	envelope := envelopedData{
		Version:              0,
		RecipientInfos:       recipients,
		EncryptedContentInfo: encContent,
	}

	// Marshal the enveloped data
	envelopeBytes, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enveloped data: %w", err)
	}

	// Create the ContentInfo
	content := contentInfo{
		ContentType: oidEnvelopedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      envelopeBytes,
		},
	}

	// Marshal the ContentInfo
	return asn1.Marshal(content)
}

// Decode parses PKCS#7 format into EncryptedData
func (f *PKCS7Format) Decode(data []byte) (*encryption.EncryptedData, error) {
	// Parse ContentInfo
	var content contentInfo
	rest, err := asn1.Unmarshal(data, &content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after ContentInfo")
	}

	// Check content type
	if !content.ContentType.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf("expected enveloped data, got %s", content.ContentType)
	}

	// Parse EnvelopedData
	var envelope envelopedData
	if _, err := asn1.Unmarshal(content.Content.Bytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal enveloped data: %w", err)
	}

	result := &encryption.EncryptedData{
		Format:     encryption.FormatPKCS7,
		Algorithm:  oidToAlgorithm(envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm),
		Recipients: make([]*encryption.RecipientInfo, 0),
		Metadata:   make(map[string]interface{}),
	}

	// Extract encrypted content
	if len(envelope.EncryptedContentInfo.EncryptedContent.Bytes) > 0 {
		result.Data = envelope.EncryptedContentInfo.EncryptedContent.Bytes
	}

	// Extract recipient information
	for _, recip := range envelope.RecipientInfos {
		recipInfo := &encryption.RecipientInfo{
			EncryptedKey:           recip.EncryptedKey,
			KeyEncryptionAlgorithm: oidToAlgorithm(recip.KeyEncryptionAlgorithm.Algorithm),
		}
		result.Recipients = append(result.Recipients, recipInfo)
	}

	// If there's only one recipient and no Recipients array was set, use the encrypted key directly
	if len(result.Recipients) == 1 && len(result.EncryptedKey) == 0 {
		result.EncryptedKey = result.Recipients[0].EncryptedKey
	}

	return result, nil
}

// getAlgorithmOID returns the OID for an encryption algorithm
func getAlgorithmOID(alg encryption.EncryptionAlgorithm) asn1.ObjectIdentifier {
	switch alg {
	case encryption.AlgorithmRSAOAEP:
		return oidRSAEncryption
	case encryption.AlgorithmAESGCM:
		return oidAES256CBC // Using AES-CBC OID as placeholder
	case encryption.AlgorithmEnvelope:
		return oidEnvelopedData
	default:
		return oidData
	}
}

// oidToAlgorithm converts an OID to an EncryptionAlgorithm
func oidToAlgorithm(oid asn1.ObjectIdentifier) encryption.EncryptionAlgorithm {
	switch {
	case oid.Equal(oidRSAEncryption):
		return encryption.AlgorithmRSAOAEP
	case oid.Equal(oidAES256CBC):
		return encryption.AlgorithmAESGCM
	case oid.Equal(oidEnvelopedData):
		return encryption.AlgorithmEnvelope
	default:
		return ""
	}
}

// parseCertificate attempts to parse a certificate from ASN.1 data
func parseCertificate(data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}