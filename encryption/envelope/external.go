// Package envelope — file external.go.
//
// External wrapping support: standards-conformant RFC 5652 CMS EnvelopedData
// where the recipient's key-encryption key lives in an external service
// (HSM, KMS, smartcard, REST API). gopki handles the ASN.1 marshalling; the
// caller supplies the wrap/unwrap operations through ExternalWrapper.
//
// EncryptWithExternalWrap deliberately returns DER-encoded CMS bytes
// (`[]byte`), NOT *encryption.EncryptedData. The latter is gopki's existing
// JSON-wrapped non-standard container produced by EncodeToCMS; that format
// is incompatible with the single-layer CMS this API produces.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ErrExternalWrapperNotImplemented is returned by EncryptWithExternalWrap /
// DecryptWithExternalWrap when the CMS marshalling is not yet wired.
var ErrExternalWrapperNotImplemented = errors.New("envelope: external wrapper not implemented")

// ExternalWrapper is implemented by callers that want gopki to assemble a
// standard RFC 5652 CMS EnvelopedData where the recipient's key-encryption
// key lives in an external service (HSM, KMS, smartcard).
//
// WrapKey is called at encrypt time with a freshly-generated DEK (typically
// 32 bytes for AES-256); the implementation returns the DEK wrapped under
// the recipient's public-key algorithm + padding. UnwrapKey is called with
// the wrapped DEK at decrypt time and must return the original DEK bytes.
type ExternalWrapper interface {
	WrapKey(ctx context.Context, dek []byte) (wrappedDEK []byte, err error)
	UnwrapKey(ctx context.Context, wrappedDEK []byte) (dek []byte, err error)
}

// EncryptWithExternalWrap encrypts data via AES-256-GCM, asks the wrapper to
// wrap the DEK, and returns a DER-encoded CMS EnvelopedData ContentInfo.
//
// recipientCert is embedded in the KeyTransRecipientInfo as issuer-and-serial-number.
// It is *not* used to perform any local crypto — the wrapper does all key wrapping.
func EncryptWithExternalWrap(
	ctx context.Context,
	data []byte,
	wrapper ExternalWrapper,
	recipientCert *x509.Certificate,
) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("envelope: data is empty")
	}
	if wrapper == nil {
		return nil, errors.New("envelope: wrapper is nil")
	}
	if recipientCert == nil {
		return nil, errors.New("envelope: recipient cert is nil")
	}

	// 1) Generate fresh AES-256 DEK and 12-byte GCM nonce.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: gen DEK: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("envelope: gen nonce: %w", err)
	}

	// 2) Bulk-encrypt data with AES-256-GCM. ciphertext includes the 16-byte tag at the end.
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: aead: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// 3) Wrap the DEK via the external service.
	wrappedDEK, err := wrapper.WrapKey(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: WrapKey: %w", err)
	}
	zeroize(dek) // best-effort wipe of the local copy

	// 4) Build OAEP params: SHA-256 hash, MGF1+SHA-256, pSpecified empty.
	sha256Alg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	mgf1Params, err := asn1.Marshal(sha256Alg)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal MGF1 params: %w", err)
	}
	emptyOctets, _ := asn1.Marshal([]byte{})
	oaepParams := oaepParamsASN1{
		HashFunc:    sha256Alg,
		MaskGenFunc: pkix.AlgorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: mgf1Params}},
		PSourceFunc: pkix.AlgorithmIdentifier{Algorithm: oidPSpecified, Parameters: asn1.RawValue{FullBytes: emptyOctets}},
	}
	oaepParamsBytes, err := asn1.Marshal(oaepParams)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal OAEP params: %w", err)
	}

	// 5) Build GCM params (IV).
	gcmParamsBytes, err := asn1.Marshal(gcmParamsASN1{Nonce: nonce, ICVLen: 12})
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal GCM params: %w", err)
	}

	// 6) Assemble the EnvelopedData.
	ed := envelopedDataASN1{
		Version: 0,
		RecipientInfos: []keyTransRecipientInfoASN1{{
			Version: 0,
			RID: issuerAndSerialASN1{
				IssuerName:   asn1.RawValue{FullBytes: recipientCert.RawIssuer},
				SerialNumber: recipientCert.SerialNumber,
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidRSAESOAEP,
				Parameters: asn1.RawValue{FullBytes: oaepParamsBytes},
			},
			EncryptedKey: wrappedDEK,
		}},
		EncryptedContentInfo: encryptedContentInfoASN1{
			ContentType: oidPKCS7Data,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidAES256GCM,
				Parameters: asn1.RawValue{FullBytes: gcmParamsBytes},
			},
			EncryptedContent: ciphertext,
		},
	}

	// 7) Wrap in ContentInfo and DER-encode.
	ci := contentInfoASN1{
		ContentType: oidPKCS7Enveloped,
		Content:     ed,
	}
	return asn1.Marshal(ci)
}

// DecryptWithExternalWrap parses a CMS EnvelopedData (produced by
// EncryptWithExternalWrap), asks the wrapper to unwrap the DEK, and AES-decrypts
// the bulk content. Returns the original plaintext.
func DecryptWithExternalWrap(
	ctx context.Context,
	cmsBytes []byte,
	wrapper ExternalWrapper,
) ([]byte, error) {
	if len(cmsBytes) == 0 {
		return nil, errors.New("envelope: cms bytes are empty")
	}
	if wrapper == nil {
		return nil, errors.New("envelope: wrapper is nil")
	}

	// 1) Parse ContentInfo.
	var ci contentInfoASN1
	if _, err := asn1.Unmarshal(cmsBytes, &ci); err != nil {
		return nil, fmt.Errorf("envelope: parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidPKCS7Enveloped) {
		return nil, fmt.Errorf("envelope: expected EnvelopedData, got %s", ci.ContentType)
	}
	ed := ci.Content

	// 2) Validate algorithms.
	if len(ed.RecipientInfos) != 1 {
		return nil, fmt.Errorf("envelope: expected exactly 1 recipient, got %d", len(ed.RecipientInfos))
	}
	rcpt := ed.RecipientInfos[0]
	if !rcpt.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP) {
		return nil, fmt.Errorf("envelope: expected RSAES-OAEP, got %s", rcpt.KeyEncryptionAlgorithm.Algorithm)
	}
	if !ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256GCM) {
		return nil, fmt.Errorf("envelope: expected AES-256-GCM, got %s", ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm)
	}

	// 3) Parse the GCM nonce out of the contentEncryptionAlgorithm parameters.
	var gcmParams gcmParamsASN1
	if _, err := asn1.Unmarshal(ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes, &gcmParams); err != nil {
		return nil, fmt.Errorf("envelope: parse GCM params: %w", err)
	}

	// 4) Ask the wrapper to unwrap the DEK.
	dek, err := wrapper.UnwrapKey(ctx, rcpt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("envelope: UnwrapKey: %w", err)
	}
	defer zeroize(dek)

	// 5) AES-GCM decrypt.
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: aead: %w", err)
	}
	plain, err := gcm.Open(nil, gcmParams.Nonce, ed.EncryptedContentInfo.EncryptedContent, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES-GCM decrypt: %w", err)
	}
	return plain, nil
}

// zeroize wipes a byte slice (best effort; the compiler may still elide).
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
