package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures - generate keys for testing
func generateRSAKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func generateECDSAKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func generateEd25519Key(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv, pub
}

func TestJWTSignVerifyRSA(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	tests := []struct {
		name string
		alg  Algorithm
	}{
		{"RS256", RS256},
		{"RS384", RS384},
		{"RS512", RS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create claims
			claims := NewClaims()
			claims.Subject = "user123"
			claims.Issuer = "test-issuer"
			claims.SetExpiration(time.Hour)

			// Sign
			token, err := Sign(claims, privKey, tt.alg, DefaultSignOptions())
			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify token has 3 parts
			parts := strings.Split(token, ".")
			assert.Len(t, parts, 3)

			// Verify
			verified, err := Verify(token, pubKey, DefaultVerifyOptions())
			require.NoError(t, err)
			assert.Equal(t, claims.Subject, verified.Subject)
			assert.Equal(t, claims.Issuer, verified.Issuer)
		})
	}
}

func TestJWTSignVerifyECDSA(t *testing.T) {
	tests := []struct {
		name  string
		alg   Algorithm
		curve elliptic.Curve
	}{
		{"ES256", ES256, elliptic.P256()},
		{"ES384", ES384, elliptic.P384()},
		{"ES512", ES512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey := generateECDSAKey(t, tt.curve)

			// Create claims
			claims := NewClaims()
			claims.Subject = "user456"
			claims.SetExpiration(time.Hour)

			// Sign
			token, err := Sign(claims, privKey, tt.alg, DefaultSignOptions())
			require.NoError(t, err)

			// Verify
			verified, err := Verify(token, pubKey, DefaultVerifyOptions())
			require.NoError(t, err)
			assert.Equal(t, claims.Subject, verified.Subject)
		})
	}
}

func TestJWTSignVerifyEd25519(t *testing.T) {
	privKey, pubKey := generateEd25519Key(t)

	// Create claims
	claims := NewClaims()
	claims.Subject = "user789"
	claims.SetExpiration(time.Hour)

	// Sign
	token, err := Sign(claims, privKey, EdDSA, DefaultSignOptions())
	require.NoError(t, err)

	// Verify
	verified, err := Verify(token, pubKey, DefaultVerifyOptions())
	require.NoError(t, err)
	assert.Equal(t, claims.Subject, verified.Subject)
}

func TestJWTSignVerifyHMAC(t *testing.T) {
	secret := []byte("my-secret-key-that-is-long-enough")

	tests := []struct {
		name string
		alg  Algorithm
	}{
		{"HS256", HS256},
		{"HS384", HS384},
		{"HS512", HS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create claims
			claims := NewClaims()
			claims.Subject = "hmac-user"
			claims.SetExpiration(time.Hour)

			// Sign
			token, err := SignWithSecret(claims, secret, tt.alg)
			require.NoError(t, err)

			// Verify
			verified, err := VerifyWithSecret(token, secret, DefaultVerifyOptions())
			require.NoError(t, err)
			assert.Equal(t, claims.Subject, verified.Subject)
		})
	}
}

func TestJWTWithKeyID(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "user-with-kid"

	opts := DefaultSignOptions()
	opts.KeyID = "key-2024-01"

	// Sign with key ID
	token, err := Sign(claims, privKey, RS256, opts)
	require.NoError(t, err)

	// Parse and check header
	parsed, err := Parse(token)
	require.NoError(t, err)
	assert.Equal(t, "key-2024-01", parsed.Header.KeyID)

	// Verify
	_, err = Verify(token, pubKey, DefaultVerifyOptions())
	require.NoError(t, err)
}

func TestClaimsValidation(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	t.Run("Expired Token", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "expired-user"
		claims.ExpiresAt = time.Now().Add(-time.Hour).Unix()

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		_, err = Verify(token, pubKey, DefaultVerifyOptions())
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("Token Not Yet Valid", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "future-user"
		claims.NotBefore = time.Now().Add(time.Hour).Unix()

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		_, err = Verify(token, pubKey, DefaultVerifyOptions())
		assert.ErrorIs(t, err, ErrTokenNotYetValid)
	})

	t.Run("Invalid Issuer", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "user"
		claims.Issuer = "wrong-issuer"
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		opts := DefaultVerifyOptions()
		opts.Validation.ValidateIssuer = true
		opts.Validation.ExpectedIssuer = "correct-issuer"

		_, err = Verify(token, pubKey, opts)
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("Invalid Audience", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "user"
		claims.Audience = []string{"api.example.com"}
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		opts := DefaultVerifyOptions()
		opts.Validation.ValidateAudience = true
		opts.Validation.ExpectedAudience = []string{"other.example.com"}

		_, err = Verify(token, pubKey, opts)
		assert.ErrorIs(t, err, ErrInvalidAudience)
	})
}

func TestAlgorithmConfusion(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "user"
	claims.SetExpiration(time.Hour)

	// Sign with RS256
	token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
	require.NoError(t, err)

	// Try to verify with different expected algorithm
	opts := &VerifyOptions{
		ExpectedAlgorithm: ES256, // Wrong algorithm!
		Validation:        DefaultValidationOptions(),
	}

	_, err = Verify(token, pubKey, opts)
	assert.ErrorIs(t, err, ErrAlgorithmMismatch)
}

func TestNoneAlgorithmRejection(t *testing.T) {
	// Manually create a token with 'none' algorithm
	header := `{"alg":"none","typ":"JWT"}`
	payload := `{"sub":"user"}`

	headerEnc := base64URLEncode([]byte(header))
	payloadEnc := base64URLEncode([]byte(payload))

	tokenWithNone := headerEnc + "." + payloadEnc + "."

	// Should be rejected during parsing
	_, err := Parse(tokenWithNone)
	assert.ErrorIs(t, err, ErrAlgorithmNone)
}

func TestTokenTooLarge(t *testing.T) {
	// Create a token larger than MaxTokenSize
	largeToken := strings.Repeat("a", MaxTokenSize+1)

	_, err := Parse(largeToken)
	assert.ErrorIs(t, err, ErrTokenTooLarge)
}

func TestCustomClaims(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "user"
	claims.Extra["role"] = "admin"
	claims.Extra["permissions"] = []string{"read", "write", "delete"}
	claims.SetExpiration(time.Hour)

	// Sign
	token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
	require.NoError(t, err)

	// Verify
	verified, err := Verify(token, pubKey, DefaultVerifyOptions())
	require.NoError(t, err)

	assert.Equal(t, "admin", verified.Extra["role"])
	perms, ok := verified.Extra["permissions"].([]interface{})
	require.True(t, ok)
	assert.Len(t, perms, 3)
}

func TestAudienceSingleAndArray(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	t.Run("Single Audience", func(t *testing.T) {
		claims := NewClaims()
		claims.Audience = []string{"api.example.com"}
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		verified, err := Verify(token, pubKey, DefaultVerifyOptions())
		require.NoError(t, err)
		assert.Len(t, verified.Audience, 1)
	})

	t.Run("Multiple Audiences", func(t *testing.T) {
		claims := NewClaims()
		claims.Audience = []string{"api.example.com", "web.example.com"}
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		verified, err := Verify(token, pubKey, DefaultVerifyOptions())
		require.NoError(t, err)
		assert.Len(t, verified.Audience, 2)
	})
}

func TestInvalidSignature(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "user"
	claims.SetExpiration(time.Hour)

	// Sign
	token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
	require.NoError(t, err)

	// Tamper with the signature
	parts := strings.Split(token, ".")
	parts[2] = "invalid-signature"
	tamperedToken := strings.Join(parts, ".")

	// Verification should fail
	_, err = Verify(tamperedToken, pubKey, DefaultVerifyOptions())
	assert.Error(t, err)
}

func TestClockSkew(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	// Token expires in 30 seconds
	claims := NewClaims()
	claims.Subject = "user"
	claims.ExpiresAt = time.Now().Add(30 * time.Second).Unix()

	token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
	require.NoError(t, err)

	// Verify with clock skew (should allow 60 seconds tolerance)
	opts := DefaultVerifyOptions()
	opts.Validation.ClockSkew = 2 * time.Minute

	// Simulate time in the future (within clock skew)
	opts.Validation.Now = func() time.Time {
		return time.Now().Add(90 * time.Second)
	}

	// Should still be valid due to clock skew
	_, err = Verify(token, pubKey, opts)
	require.NoError(t, err)
}

func TestParse(t *testing.T) {
	privKey, _ := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "user123"
	claims.Issuer = "test"
	claims.SetExpiration(time.Hour)

	token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
	require.NoError(t, err)

	// Parse without verification
	parsed, err := Parse(token)
	require.NoError(t, err)

	assert.Equal(t, RS256, parsed.Header.Algorithm)
	assert.Equal(t, "JWT", parsed.Header.Type)
	assert.Equal(t, "user123", parsed.Claims.Subject)
	assert.Equal(t, "test", parsed.Claims.Issuer)
}
