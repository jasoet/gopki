// Package signing — file external.go.
//
// External signing support: PKCS#7 SignedData where the actual signature
// computation is delegated to an external service (HSM, KMS, smartcard,
// REST API). gopki handles the ASN.1 marshalling; the caller supplies the
// signature bytes.
package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/jasoet/gopki/cert"
)

// ErrExternalSignerNotImplemented is reserved for future external-signer code
// paths (e.g., ECDSA/Ed25519/PSS) that are not yet wired. The v1.25.0 RSA +
// SHA-256 + PKCS#1 v1.5 + detached path is fully implemented and no longer
// returns this sentinel; it remains as exported public API for forward
// compatibility.
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
	// SignDocumentWithExternalSigner cross-checks this against the supplied
	// certificate's public key and rejects the call if they don't match —
	// catching a wrong-cert bug at sign-time rather than verify-time.
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
// is a future extension. PSS is also a future extension; switching to PSS only
// requires choosing a different OID for the signatureAlgorithm field — the
// interface itself returns raw bytes and is unchanged.
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

	// Fix v1.25.0 algorithm matrix: SHA-256 + PKCS#1 v1.5 RSA + detached.
	hashAlg := opts.HashAlgorithm
	if hashAlg == 0 {
		hashAlg = crypto.SHA256
	}
	if hashAlg != crypto.SHA256 {
		return nil, fmt.Errorf("external signer v1.25.0 supports SHA-256 only; got %v", hashAlg)
	}

	// Cross-check: the external signer's public key must match the certificate's.
	// Catches the common bug of passing the wrong cert at sign-time rather than verify-time.
	signerRSAPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("external signer public key must be *rsa.PublicKey, got %T", signer.Public())
	}
	certRSAPub, ok := certificate.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key must be *rsa.PublicKey, got %T", certificate.Certificate.PublicKey)
	}
	if signerRSAPub.N.Cmp(certRSAPub.N) != 0 || signerRSAPub.E != certRSAPub.E {
		return nil, fmt.Errorf("external signer public key does not match certificate public key")
	}

	// 1) Compute the content message digest (over the data we are detached-signing).
	h := hashAlg.New()
	h.Write(data)
	messageDigest := h.Sum(nil)

	// 2) Build the SignedAttributes SET (contentType, messageDigest, signingTime).
	signedAttrs, err := buildSignedAttrs(messageDigest, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("build signedAttrs: %w", err)
	}

	// 3) Marshal SignedAttributes as a canonical SET OF Attribute for signing.
	signedAttrsBytes, err := marshalSignedAttrsForSigning(signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("marshal signedAttrs for signing: %w", err)
	}

	// 4) Delegate the actual signature to the external signer. HSK will hash
	//    signedAttrsBytes internally and return RSA(DigestInfo(SHA256, hash)).
	rawSignature, err := signer.Sign(ctx, signedAttrsBytes, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("external signer: %w", err)
	}

	// 5) Assemble SignerInfo with the external signature.
	si, err := buildSignerInfo(certificate.Certificate, signedAttrs, rawSignature)
	if err != nil {
		return nil, fmt.Errorf("build SignerInfo: %w", err)
	}

	// 6) Wrap in SignedData (detached: EncapContentInfo with no eContent).
	sd, err := buildSignedData(certificate.Certificate, si, opts.ExtraCertificates)
	if err != nil {
		return nil, fmt.Errorf("build SignedData: %w", err)
	}

	// 7) Wrap in ContentInfo and DER-marshal.
	ci := contentInfoASN1{
		ContentType: oidPKCS7SignedData,
		Content:     sd,
	}
	pkcs7Bytes, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("marshal ContentInfo: %w", err)
	}

	return &Signature{
		Format:           FormatPKCS7Detached,
		Algorithm:        AlgorithmRSA,
		HashAlgorithm:    hashAlg,
		Data:             pkcs7Bytes,
		Digest:           messageDigest,
		Certificate:      certificate.Certificate,
		CertificateChain: opts.ExtraCertificates,
	}, nil
}

// buildSignedAttrs constructs the three mandatory PKCS#9 attributes.
func buildSignedAttrs(messageDigest []byte, signingTime time.Time) ([]attributeASN1, error) {
	contentTypeVal, err := asn1.Marshal(oidPKCS7Data)
	if err != nil {
		return nil, err
	}
	msgDigestVal, err := asn1.Marshal(messageDigest)
	if err != nil {
		return nil, err
	}
	timeVal, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, err
	}
	return []attributeASN1{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: contentTypeVal}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: msgDigestVal}}},
		{Type: oidSigningTime, Values: []asn1.RawValue{{FullBytes: timeVal}}},
	}, nil
}

// marshalSignedAttrsForSigning marshals the SignedAttributes SET in its
// canonical SET OF form (not [0] IMPLICIT). This is the form that gets hashed
// and signed per RFC 5652 §5.4.
func marshalSignedAttrsForSigning(attrs []attributeASN1) ([]byte, error) {
	// We marshal a struct with an `asn1:"set"`-tagged field so that
	// encoding/asn1 produces a SET OF Attribute (universal tag 17).
	wrapper := struct {
		Attrs []attributeASN1 `asn1:"set"`
	}{Attrs: attrs}
	full, err := asn1.Marshal(wrapper)
	if err != nil {
		return nil, err
	}
	// asn1.Marshal puts a SEQUENCE around the struct. We need the inner SET bytes only.
	// Re-parse to extract: the inner element is the SET OF Attribute.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(full, &raw); err != nil {
		return nil, err
	}
	// raw.Bytes is the contents of the SEQUENCE wrapper, which is the SET OF Attribute
	// (already in TLV form). Return the SET as a TLV by re-wrapping.
	return raw.Bytes, nil
}

// buildSignerInfo assembles the SignerInfo with the externally-provided signature.
func buildSignerInfo(c *x509.Certificate, attrs []attributeASN1, sig []byte) (signerInfoASN1, error) {
	return signerInfoASN1{
		Version: 1,
		IssuerAndSerial: issuerAndSerialASN1{
			IssuerName:   asn1.RawValue{FullBytes: c.RawIssuer},
			SerialNumber: c.SerialNumber,
		},
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
		AuthenticatedAttributes:   attrs,
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
		EncryptedDigest:           sig,
	}, nil
}

// buildSignedData assembles the SignedData, embedding the signer cert (+ optional chain)
// in the `certificates [0] IMPLICIT` field.
func buildSignedData(signerCert *x509.Certificate, si signerInfoASN1, chain []*x509.Certificate) (signedDataASN1, error) {
	var certsBuf bytes.Buffer
	certsBuf.Write(signerCert.Raw)
	for _, c := range chain {
		certsBuf.Write(c.Raw)
	}
	return signedDataASN1{
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}},
		EncapContentInfo: encapsulatedContentInfoASN1{
			ContentType: oidPKCS7Data,
			// Detached: Content omitted.
		},
		Certificates: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certsBuf.Bytes()},
		SignerInfos:  []signerInfoASN1{si},
	}, nil
}
