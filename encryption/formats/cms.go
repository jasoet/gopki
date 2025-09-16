package formats

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/jasoet/gopki/encryption"
)

// CMSFormat handles CMS (Cryptographic Message Syntax) format for encrypted data
// CMS is the successor to PKCS#7 and provides additional features
type CMSFormat struct{}

// NewCMSFormat creates a new CMS format handler
func NewCMSFormat() *CMSFormat {
	return &CMSFormat{}
}

// Name returns the format name
func (f *CMSFormat) Name() string {
	return string(encryption.FormatCMS)
}

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
	IssuerAndSerial *issuerAndSerial `asn1:"optional"`
	SubjectKeyId    []byte `asn1:"implicit,optional,tag:0"`
}

// CMSEncryptedContentInfo structure
type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"implicit,optional,tag:0"`
}

// Encode converts EncryptedData to CMS format
func (f *CMSFormat) Encode(data *encryption.EncryptedData) ([]byte, error) {
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
				IssuerAndSerial: &issuerAndSerial{
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
				IssuerAndSerial: &issuerAndSerial{
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
			recipient.RecipientIdentifier.IssuerAndSerial = nil
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

// Decode parses CMS format into EncryptedData
func (f *CMSFormat) Decode(data []byte) (*encryption.EncryptedData, error) {
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

	result := &encryption.EncryptedData{
		Format:     encryption.FormatCMS,
		Algorithm:  oidToAlgorithm(cms.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm),
		Data:       cms.EncryptedContentInfo.EncryptedContent,
		Recipients: make([]*encryption.RecipientInfo, 0),
		Metadata:   make(map[string]interface{}),
	}

	// Extract recipient information
	for _, recip := range cms.RecipientInfos {
		recipInfo := &encryption.RecipientInfo{
			EncryptedKey:           recip.EncryptedKey,
			KeyEncryptionAlgorithm: oidToAlgorithm(recip.KeyEncryptionAlgorithm.Algorithm),
		}

		// Extract key ID if available
		if len(recip.RecipientIdentifier.SubjectKeyId) > 0 {
			recipInfo.KeyID = recip.RecipientIdentifier.SubjectKeyId
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