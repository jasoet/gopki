package signing_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/signing"
)

// localSigner is a test ExternalSigner that uses a local RSA private key.
// It hashes signedAttrsBytes with hashAlg and signs the hash with PKCS1v15.
// This is what the real HSK signer does conceptually (HSK hashes internally).
type localSigner struct {
	priv *rsa.PrivateKey
}

func (s *localSigner) Sign(_ context.Context, signedAttrsBytes []byte, hashAlg crypto.Hash) ([]byte, error) {
	h := hashAlg.New()
	h.Write(signedAttrsBytes)
	return rsa.SignPKCS1v15(rand.Reader, s.priv, hashAlg, h.Sum(nil))
}

func (s *localSigner) Public() crypto.PublicKey { return &s.priv.PublicKey }

// Compile-time assertion that *localSigner satisfies ExternalSigner.
var _ signing.ExternalSigner = (*localSigner)(nil)

func TestExternalSigner_SkeletonReturnsErrNotImplemented(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	s := &localSigner{priv: priv}
	_, err = signing.SignDocumentWithExternalSigner(context.Background(), []byte("hi"), s, nil, signing.SignOptions{})
	// nil cert → ErrMissingCertificate, NOT NotImplemented. This guards the early validation.
	if !errors.Is(err, signing.ErrMissingCertificate) {
		t.Fatalf("expected ErrMissingCertificate, got: %v", err)
	}
}

func TestSignDocumentWithExternalSigner_RoundTripWithVerifySignature(t *testing.T) {
	// Generate an RSA keypair and a self-signed cert.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-external-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	gopkiCert := &cert.Certificate{Certificate: x509Cert}

	data := []byte("payload to sign")
	signer := &localSigner{priv: priv}

	sig, err := signing.SignDocumentWithExternalSigner(context.Background(), data, signer, gopkiCert, signing.SignOptions{
		Format:        signing.FormatPKCS7Detached,
		HashAlgorithm: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("SignDocumentWithExternalSigner: %v", err)
	}
	if sig == nil || len(sig.Data) == 0 {
		t.Fatalf("returned signature is empty")
	}

	// Verify by feeding the result through gopki's existing VerifySignature,
	// which uses smallstep/pkcs7.Parse + Verify under the hood. This is the
	// gate that proves our manual ASN.1 is byte-compatible.
	sig.Format = signing.FormatPKCS7Detached
	if err := signing.VerifySignature(data, sig, signing.DefaultVerifyOptions()); err != nil {
		t.Fatalf("VerifySignature on external-signer output: %v", err)
	}
}
