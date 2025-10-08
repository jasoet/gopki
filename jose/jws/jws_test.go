package jws

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/jasoet/gopki/jose/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures
func generateRSAKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func generateECDSAKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func generateEd25519Key(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv, pub
}

func TestCompactSignVerify(t *testing.T) {
	payload := []byte(`{"action": "transfer", "amount": 1000}`)

	tests := []struct {
		name      string
		alg       jwt.Algorithm
		setupKeys func(t *testing.T) (interface{}, interface{})
	}{
		{
			name: "RS256",
			alg:  jwt.RS256,
			setupKeys: func(t *testing.T) (interface{}, interface{}) {
				priv, pub := generateRSAKey(t)
				return priv, pub
			},
		},
		{
			name: "ES256",
			alg:  jwt.ES256,
			setupKeys: func(t *testing.T) (interface{}, interface{}) {
				priv, pub := generateECDSAKey(t)
				return priv, pub
			},
		},
		{
			name: "EdDSA",
			alg:  jwt.EdDSA,
			setupKeys: func(t *testing.T) (interface{}, interface{}) {
				priv, pub := generateEd25519Key(t)
				return priv, pub
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey := tt.setupKeys(t)

			// Sign
			var token string
			var err error
			switch priv := privKey.(type) {
			case *rsa.PrivateKey:
				token, err = SignCompact(payload, priv, tt.alg, "test-key")
			case *ecdsa.PrivateKey:
				token, err = SignCompact(payload, priv, tt.alg, "test-key")
			case ed25519.PrivateKey:
				token, err = SignCompact(payload, priv, tt.alg, "test-key")
			}
			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify
			var verified []byte
			switch pub := pubKey.(type) {
			case *rsa.PublicKey:
				verified, err = VerifyCompact(token, pub, tt.alg)
			case *ecdsa.PublicKey:
				verified, err = VerifyCompact(token, pub, tt.alg)
			case ed25519.PublicKey:
				verified, err = VerifyCompact(token, pub, tt.alg)
			}
			require.NoError(t, err)

			// Verify payload matches
			var original, result map[string]interface{}
			require.NoError(t, json.Unmarshal(payload, &original))
			require.NoError(t, json.Unmarshal(verified, &result))
			assert.Equal(t, original, result)
		})
	}
}

func TestCompactWithHMAC(t *testing.T) {
	payload := []byte(`{"message": "hello world"}`)
	secret := []byte("my-secret-key-that-is-long-enough")

	// Sign
	token, err := SignCompactWithSecret(payload, secret, jwt.HS256)
	require.NoError(t, err)

	// Verify
	verified, err := VerifyCompactWithSecret(token, secret, jwt.HS256)
	require.NoError(t, err)

	var original, result map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &original))
	require.NoError(t, json.Unmarshal(verified, &result))
	assert.Equal(t, original, result)
}

func TestJSONSerialization(t *testing.T) {
	payload := []byte(`{"data": "test payload"}`)

	// Generate multiple keys
	rsaPriv, rsaPub := generateRSAKey(t)
	ecPriv, ecPub := generateECDSAKey(t)

	// Create signers
	signers := []*Signer{
		{
			Key:       rsaPriv,
			Algorithm: jwt.RS256,
			KeyID:     "rsa-key-1",
		},
		{
			Key:       ecPriv,
			Algorithm: jwt.ES256,
			KeyID:     "ec-key-1",
		},
	}

	// Sign
	token, err := SignJSON(payload, signers)
	require.NoError(t, err)
	assert.Len(t, token.Signatures, 2)

	// Verify with both verifiers
	verifiers := []*Verifier{
		{
			Key:       rsaPub,
			Algorithm: jwt.RS256,
			KeyID:     "rsa-key-1",
		},
		{
			Key:       ecPub,
			Algorithm: jwt.ES256,
			KeyID:     "ec-key-1",
		},
	}

	verified, err := VerifyJSON(token, verifiers)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestJSONSerializationWithOneVerifier(t *testing.T) {
	payload := []byte(`{"data": "test"}`)

	rsaPriv, rsaPub := generateRSAKey(t)
	ecPriv, _ := generateECDSAKey(t)

	// Sign with both
	signers := []*Signer{
		{Key: rsaPriv, Algorithm: jwt.RS256, KeyID: "rsa"},
		{Key: ecPriv, Algorithm: jwt.ES256, KeyID: "ec"},
	}

	token, err := SignJSON(payload, signers)
	require.NoError(t, err)

	// Verify with only RSA key (should still pass)
	verifiers := []*Verifier{
		{Key: rsaPub, Algorithm: jwt.RS256, KeyID: "rsa"},
	}

	verified, err := VerifyJSON(token, verifiers)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestDetachedContent(t *testing.T) {
	content := []byte("This is a large file that we don't want to include in the JWS")
	privKey, pubKey := generateRSAKey(t)

	// Sign detached
	detached, err := SignDetached(content, privKey, jwt.RS256, "test-key")
	require.NoError(t, err)

	// Should have format: header..signature (double dot)
	assert.Contains(t, detached, "..")

	// Verify detached
	err = VerifyDetached(detached, content, pubKey, jwt.RS256)
	require.NoError(t, err)
}

func TestDetachedWithWrongContent(t *testing.T) {
	content := []byte("original content")
	wrongContent := []byte("different content")

	privKey, pubKey := generateRSAKey(t)

	// Sign with original
	detached, err := SignDetached(content, privKey, jwt.RS256, "test-key")
	require.NoError(t, err)

	// Verify with wrong content should fail
	err = VerifyDetached(detached, wrongContent, pubKey, jwt.RS256)
	assert.Error(t, err)
}

func TestDetachedWithHMAC(t *testing.T) {
	content := []byte("secret message")
	secret := []byte("shared-secret-key")

	// Sign
	detached, err := SignDetachedWithSecret(content, secret, jwt.HS256)
	require.NoError(t, err)

	// Verify
	err = VerifyDetachedWithSecret(detached, content, secret, jwt.HS256)
	require.NoError(t, err)
}

func TestJSONMarshalUnmarshal(t *testing.T) {
	payload := []byte(`{"test": "data"}`)
	privKey, _ := generateRSAKey(t)

	signer := &Signer{
		Key:       privKey,
		Algorithm: jwt.RS256,
		KeyID:     "test-key",
	}

	// Sign
	token, err := SignJSON(payload, []*Signer{signer})
	require.NoError(t, err)

	// Marshal to JSON
	jsonData, err := token.Marshal()
	require.NoError(t, err)

	// Unmarshal
	parsed, err := UnmarshalJSON(jsonData)
	require.NoError(t, err)

	assert.Equal(t, token.Payload, parsed.Payload)
	assert.Len(t, parsed.Signatures, 1)
}

func TestErrorCases(t *testing.T) {
	t.Run("Empty payload", func(t *testing.T) {
		privKey, _ := generateRSAKey(t)
		_, err := SignCompact([]byte{}, privKey, jwt.RS256, "")
		assert.Error(t, err)
	})

	t.Run("No signers", func(t *testing.T) {
		payload := []byte("test")
		_, err := SignJSON(payload, []*Signer{})
		assert.ErrorIs(t, err, ErrNoSignatures)
	})

	t.Run("Invalid detached format", func(t *testing.T) {
		_, pubKey := generateRSAKey(t)
		// Invalid format (should be header..signature)
		err := VerifyDetached("header.payload.signature", []byte("content"), pubKey, jwt.RS256)
		assert.ErrorIs(t, err, ErrInvalidDetachedFormat)
	})

	t.Run("No valid signature", func(t *testing.T) {
		payload := []byte("test")
		privKey, _ := generateRSAKey(t)
		_, wrongPubKey := generateRSAKey(t)

		signer := &Signer{
			Key:       privKey,
			Algorithm: jwt.RS256,
		}

		token, err := SignJSON(payload, []*Signer{signer})
		require.NoError(t, err)

		verifier := &Verifier{
			Key:       wrongPubKey,
			Algorithm: jwt.RS256,
		}

		_, err = VerifyJSON(token, []*Verifier{verifier})
		assert.ErrorIs(t, err, ErrNoValidSignature)
	})
}

func TestUnprotectedHeader(t *testing.T) {
	payload := []byte(`{"data": "test"}`)
	privKey, pubKey := generateRSAKey(t)

	signer := &Signer{
		Key:       privKey,
		Algorithm: jwt.RS256,
		KeyID:     "key-1",
		UnprotectedHeader: map[string]interface{}{
			"jku": "https://example.com/keys",
			"x5u": "https://example.com/certs",
		},
	}

	// Sign
	token, err := SignJSON(payload, []*Signer{signer})
	require.NoError(t, err)

	// Check unprotected header is present
	assert.NotNil(t, token.Signatures[0].Header)
	assert.Equal(t, "https://example.com/keys", token.Signatures[0].Header["jku"])

	// Verify should still work
	verifier := &Verifier{
		Key:       pubKey,
		Algorithm: jwt.RS256,
	}

	_, err = VerifyJSON(token, []*Verifier{verifier})
	require.NoError(t, err)
}

func TestJSONSerializationWithHMAC(t *testing.T) {
	payload := []byte(`{"message": "test with HMAC"}`)
	secret := []byte("my-secret-key-for-hmac-signing")

	// Create HMAC signer
	signer := &Signer{
		Key:       secret,
		Algorithm: jwt.HS256,
		KeyID:     "hmac-key-1",
	}

	// Sign
	token, err := SignJSON(payload, []*Signer{signer})
	require.NoError(t, err)
	assert.Len(t, token.Signatures, 1)

	// Verify with HMAC
	verifier := &Verifier{
		Key:       secret,
		Algorithm: jwt.HS256,
		KeyID:     "hmac-key-1",
	}

	verified, err := VerifyJSON(token, []*Verifier{verifier})
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestJSONSerializationWithPSS(t *testing.T) {
	payload := []byte(`{"test": "PSS algorithm"}`)
	privKey, pubKey := generateRSAKey(t)

	// Test PS256
	signer := &Signer{
		Key:       privKey,
		Algorithm: jwt.PS256,
		KeyID:     "pss-key",
	}

	token, err := SignJSON(payload, []*Signer{signer})
	require.NoError(t, err)

	verifier := &Verifier{
		Key:       pubKey,
		Algorithm: jwt.PS256,
	}

	verified, err := VerifyJSON(token, []*Verifier{verifier})
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestUnmarshalJSONErrors(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		_, err := UnmarshalJSON([]byte("not valid json"))
		assert.Error(t, err)
	})

	t.Run("Missing payload", func(t *testing.T) {
		data := []byte(`{"signatures": [{"signature": "test"}]}`)
		_, err := UnmarshalJSON(data)
		assert.ErrorIs(t, err, ErrInvalidJSON)
	})

	t.Run("Missing signatures", func(t *testing.T) {
		data := []byte(`{"payload": "test"}`)
		_, err := UnmarshalJSON(data)
		assert.ErrorIs(t, err, ErrNoSignatures)
	})
}

func TestMixedAlgorithmsJSON(t *testing.T) {
	payload := []byte(`{"data": "mixed algorithms"}`)

	// Generate different key types
	rsaPriv, rsaPub := generateRSAKey(t)
	ecPriv, ecPub := generateECDSAKey(t)
	secret := []byte("hmac-secret-key-for-mixed-test")

	// Create signers with different algorithms
	signers := []*Signer{
		{Key: rsaPriv, Algorithm: jwt.RS256, KeyID: "rsa"},
		{Key: ecPriv, Algorithm: jwt.ES256, KeyID: "ec"},
		{Key: secret, Algorithm: jwt.HS256, KeyID: "hmac"},
	}

	// Sign with all three
	token, err := SignJSON(payload, signers)
	require.NoError(t, err)
	assert.Len(t, token.Signatures, 3)

	// Verify with each key individually
	verifiers := []*Verifier{
		{Key: rsaPub, Algorithm: jwt.RS256, KeyID: "rsa"},
	}
	verified, err := VerifyJSON(token, verifiers)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)

	// Verify with EC key
	verifiers = []*Verifier{
		{Key: ecPub, Algorithm: jwt.ES256, KeyID: "ec"},
	}
	verified, err = VerifyJSON(token, verifiers)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)

	// Verify with HMAC key
	verifiers = []*Verifier{
		{Key: secret, Algorithm: jwt.HS256, KeyID: "hmac"},
	}
	verified, err = VerifyJSON(token, verifiers)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

// Test additional hash algorithms (SHA-384, SHA-512)
func TestAdditionalHashAlgorithms(t *testing.T) {
	payload := []byte("test-data")

	t.Run("RS384", func(t *testing.T) {
		privKey, pubKey := generateRSAKey(t)
		token, err := SignCompact(payload, privKey, jwt.RS384, "test-key")
		require.NoError(t, err)

		_, err = VerifyCompact(token, pubKey, jwt.RS384)
		require.NoError(t, err)
	})

	t.Run("RS512", func(t *testing.T) {
		privKey, pubKey := generateRSAKey(t)
		token, err := SignCompact(payload, privKey, jwt.RS512, "test-key")
		require.NoError(t, err)

		_, err = VerifyCompact(token, pubKey, jwt.RS512)
		require.NoError(t, err)
	})

	t.Run("ES384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		pubKey := &privateKey.PublicKey

		token, err := SignCompact(payload, privateKey, jwt.ES384, "test-key")
		require.NoError(t, err)

		_, err = VerifyCompact(token, pubKey, jwt.ES384)
		require.NoError(t, err)
	})

	t.Run("ES512", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)
		pubKey := &privateKey.PublicKey

		token, err := SignCompact(payload, privateKey, jwt.ES512, "test-key")
		require.NoError(t, err)

		_, err = VerifyCompact(token, pubKey, jwt.ES512)
		require.NoError(t, err)
	})

	t.Run("HS384", func(t *testing.T) {
		secret := []byte("my-secret-key-for-hs384-testing")
		token, err := SignCompactWithSecret(payload, secret, jwt.HS384)
		require.NoError(t, err)

		_, err = VerifyCompactWithSecret(token, secret, jwt.HS384)
		require.NoError(t, err)
	})

	t.Run("HS512", func(t *testing.T) {
		secret := []byte("my-secret-key-for-hs512-testing")
		token, err := SignCompactWithSecret(payload, secret, jwt.HS512)
		require.NoError(t, err)

		_, err = VerifyCompactWithSecret(token, secret, jwt.HS512)
		require.NoError(t, err)
	})
}

// Test unsupported algorithm errors
func TestUnsupportedAlgorithms(t *testing.T) {
	payload := []byte("test")

	t.Run("Unsupported Sign algorithm", func(t *testing.T) {
		privKey, _ := generateRSAKey(t)
		_, err := SignCompact(payload, privKey, "UNSUPPORTED", "test-key")
		assert.Error(t, err)
	})

	t.Run("Unsupported Verify algorithm", func(t *testing.T) {
		_, pubKey := generateRSAKey(t)
		// Create a valid token structure but with unsupported alg
		token := "eyJhbGciOiJVTlNVUFBPUlRFRCJ9.cGF5bG9hZA.c2lnbmF0dXJl"
		_, err := VerifyCompact(token, pubKey, "UNSUPPORTED")
		assert.Error(t, err)
	})
}

// Test detached signature with additional key types
func TestDetachedWithECDSA(t *testing.T) {
	content := []byte("important document")
	privKey, pubKey := generateECDSAKey(t)

	// Sign detached
	detached, err := SignDetached(content, privKey, jwt.ES256, "ec-key")
	require.NoError(t, err)

	// Verify
	err = VerifyDetached(detached, content, pubKey, jwt.ES256)
	require.NoError(t, err)
}
