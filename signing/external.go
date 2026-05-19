// Package signing — file external.go.
//
// External signing support: PKCS#7 SignedData where the actual signature
// computation is delegated to an external service (HSM, KMS, smartcard,
// REST API). gopki handles the ASN.1 marshalling; the caller supplies the
// signature bytes.
package signing

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/jasoet/gopki/cert"
)

// ErrExternalSignerNotImplemented is returned by SignDocumentWithExternalSigner
// when the marshalling code path is not yet wired (Task A1 skeleton only).
var ErrExternalSignerNotImplemented = errors.New("signing: SignDocumentWithExternalSigner not implemented")

// ExternalSigner is implemented by callers that want gopki to assemble a
// PKCS#7 SignedData envelope around a signature computed by an external
// service.
//
// Unlike crypto.Signer, the Sign method receives the *marshalled signedAttrs
// bytes* — not a digest. Implementations are expected to hash those bytes
// internally (or send them to a service that does) and return a raw RSA
// signature whose effective payload is DigestInfo(hashAlg, hash(signedAttrsBytes)).
// The hashAlg parameter tells the implementation which digest algorithm the
// PKCS#7 SignedData expects.
type ExternalSigner interface {
	// Sign signs the canonical DER encoding of the SignedAttributes SET.
	// signedAttrsBytes is the input the external service must hash and sign.
	// hashAlg matches the digestAlgorithm field of the SignedData.
	Sign(ctx context.Context, signedAttrsBytes []byte, hashAlg crypto.Hash) ([]byte, error)

	// Public returns the public key matching the external signer's private key.
	// Used to validate that the supplied certificate's public key matches.
	Public() crypto.PublicKey
}

// SignDocumentWithExternalSigner builds a PKCS#7 SignedData (detached) using
// an ExternalSigner for the signature step. All ASN.1 marshalling, digest
// algorithm selection, signedAttrs construction, and SignerInfo assembly are
// handled by gopki — only the raw signature is delegated.
//
// The returned *Signature has its Data field populated with the DER-encoded
// PKCS#7 ContentInfo. Format is fixed to FormatPKCS7Detached; HashAlgorithm
// defaults to SHA-256 if opts.HashAlgorithm == 0.
//
// Only RSA keys are supported in v1.25.0. ECDSA/Ed25519 with external signers
// is a future extension.
func SignDocumentWithExternalSigner(
	ctx context.Context,
	data []byte,
	signer ExternalSigner,
	certificate *cert.Certificate,
	opts SignOptions,
) (*Signature, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot sign empty data")
	}
	if signer == nil {
		return nil, fmt.Errorf("external signer is nil")
	}
	if certificate == nil || certificate.Certificate == nil {
		return nil, ErrMissingCertificate
	}
	return nil, ErrExternalSignerNotImplemented
}
