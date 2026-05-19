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
	"crypto/x509"
	"errors"
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
	return nil, ErrExternalWrapperNotImplemented
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
	return nil, ErrExternalWrapperNotImplemented
}
