package envelope_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

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
