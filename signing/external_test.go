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
	"strings"
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

func TestSignDocumentWithExternalSigner_NilCertReturnsErrMissingCertificate(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	s := &localSigner{priv: priv}
	_, err = signing.SignDocumentWithExternalSigner(context.Background(), []byte("hi"), s, nil, signing.SignOptions{})
	// nil cert must return ErrMissingCertificate; this guards the early-validation order.
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

func TestSignDocumentWithExternalSigner_RejectsMismatchedCert(t *testing.T) {
	// Signer has one key; cert has a DIFFERENT key. Must fail at sign-time.
	signerPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	certPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "mismatched"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certPriv.PublicKey, certPriv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	x509Cert, _ := x509.ParseCertificate(certDER)
	gopkiCert := &cert.Certificate{Certificate: x509Cert}

	signer := &localSigner{priv: signerPriv}
	_, err = signing.SignDocumentWithExternalSigner(context.Background(), []byte("x"), signer, gopkiCert, signing.SignOptions{HashAlgorithm: crypto.SHA256})
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("expected mismatch error, got: %v", err)
	}
}

func TestSignDocumentWithExternalSigner_RejectsNonRSASignerPublic(t *testing.T) {
	// A signer whose Public() returns a non-RSA type must be rejected.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "non-rsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	x509Cert, _ := x509.ParseCertificate(certDER)
	gopkiCert := &cert.Certificate{Certificate: x509Cert}

	bogus := &bogusPubSigner{}
	_, err := signing.SignDocumentWithExternalSigner(context.Background(), []byte("x"), bogus, gopkiCert, signing.SignOptions{HashAlgorithm: crypto.SHA256})
	if err == nil {
		t.Fatal("expected non-RSA-pub error, got nil")
	}
	if !strings.Contains(err.Error(), "must be *rsa.PublicKey") {
		t.Errorf("expected non-RSA error, got: %v", err)
	}
}

// bogusPubSigner returns a non-RSA "public key" to exercise the cross-check guard.
type bogusPubSigner struct{}

func (bogusPubSigner) Sign(_ context.Context, _ []byte, _ crypto.Hash) ([]byte, error) {
	return nil, nil
}
func (bogusPubSigner) Public() crypto.PublicKey { return struct{}{} }
