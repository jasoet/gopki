package envelope_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jasoet/gopki/encryption/envelope"
)

// localWrapper is a test ExternalWrapper that uses a local RSA keypair with
// RSA-OAEP-SHA256. This is what the real HSK encryptor does conceptually.
type localWrapper struct {
	priv *rsa.PrivateKey
}

func (w *localWrapper) WrapKey(_ context.Context, dek []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, &w.priv.PublicKey, dek, nil)
}

func (w *localWrapper) UnwrapKey(_ context.Context, wrappedDEK []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, w.priv, wrappedDEK, nil)
}

var _ envelope.ExternalWrapper = (*localWrapper)(nil)

func TestEncryptWithExternalWrap_SkeletonReturnsErrNotImplemented(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	w := &localWrapper{priv: priv}
	_, err = envelope.EncryptWithExternalWrap(context.Background(), []byte("hi"), w, nil)
	if err == nil || err.Error() != "envelope: recipient cert is nil" {
		t.Fatalf("expected recipient-cert error, got: %v", err)
	}
}

func TestEncryptDecryptWithExternalWrap_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "test-external-wrapper"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	w := &localWrapper{priv: priv}
	plaintext := []byte("payload to envelope-encrypt")

	cmsBytes, err := envelope.EncryptWithExternalWrap(context.Background(), plaintext, w, x509Cert)
	if err != nil {
		t.Fatalf("EncryptWithExternalWrap: %v", err)
	}
	if len(cmsBytes) == 0 {
		t.Fatalf("CMS bytes empty")
	}

	recovered, err := envelope.DecryptWithExternalWrap(context.Background(), cmsBytes, w)
	if err != nil {
		t.Fatalf("DecryptWithExternalWrap: %v", err)
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("round-trip mismatch: %q vs %q", plaintext, recovered)
	}
}
