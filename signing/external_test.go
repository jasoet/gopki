package signing_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

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
