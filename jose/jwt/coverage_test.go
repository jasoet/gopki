package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional tests to increase coverage

func TestAlgorithmHelpers(t *testing.T) {
	t.Run("IsECDSA", func(t *testing.T) {
		assert.True(t, ES256.IsECDSA())
		assert.True(t, ES384.IsECDSA())
		assert.True(t, ES512.IsECDSA())
		assert.False(t, RS256.IsECDSA())
		assert.False(t, EdDSA.IsECDSA())
	})

	t.Run("IsEdDSA", func(t *testing.T) {
		assert.True(t, EdDSA.IsEdDSA())
		assert.False(t, ES256.IsEdDSA())
		assert.False(t, RS256.IsEdDSA())
	})
}

func TestClaimsHelpers(t *testing.T) {
	t.Run("SetNotBefore", func(t *testing.T) {
		claims := NewClaims()
		claims.SetNotBefore(time.Hour)
		assert.True(t, claims.NotBefore > time.Now().Unix())
	})

	t.Run("IsExpired", func(t *testing.T) {
		claims := NewClaims()

		// Not expired (no expiry set)
		assert.False(t, claims.IsExpired())

		// Expired
		claims.ExpiresAt = time.Now().Add(-time.Hour).Unix()
		assert.True(t, claims.IsExpired())

		// Not expired
		claims.ExpiresAt = time.Now().Add(time.Hour).Unix()
		assert.False(t, claims.IsExpired())
	})

	t.Run("IsNotYetValid", func(t *testing.T) {
		claims := NewClaims()

		// Not restricted (no nbf set)
		assert.False(t, claims.IsNotYetValid())

		// Not yet valid
		claims.NotBefore = time.Now().Add(time.Hour).Unix()
		assert.True(t, claims.IsNotYetValid())

		// Already valid
		claims.NotBefore = time.Now().Add(-time.Hour).Unix()
		assert.False(t, claims.IsNotYetValid())
	})
}

func TestTokenString(t *testing.T) {
	privKey, _ := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "user"
	claims.SetExpiration(time.Hour)

	token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
	require.NoError(t, err)

	// Parse and test String method
	parsed, err := Parse(token)
	require.NoError(t, err)

	assert.Equal(t, token, parsed.String())
}

func TestInvalidTokenFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"Empty", ""},
		{"One part", "header"},
		{"Two parts", "header.payload"},
		{"Four parts", "a.b.c.d"},
		{"Invalid base64", "invalid@@@.payload.signature"},
		{"Invalid header JSON", "aW52YWxpZC1qc29u.payload.signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.token)
			assert.Error(t, err)
		})
	}
}

func TestMixedAlgorithmErrors(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)
	secret := []byte("secret")

	t.Run("HMAC with Sign function", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "user"

		// Should error - HMAC requires SignWithSecret
		_, err := Sign(claims, privKey, HS256, DefaultSignOptions())
		assert.Error(t, err)
	})

	t.Run("RSA with SignWithSecret", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "user"

		// Should error - RSA requires Sign
		_, err := SignWithSecret(claims, secret, RS256)
		assert.Error(t, err)
	})

	t.Run("HMAC token with Verify", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "user"
		claims.SetExpiration(time.Hour)

		token, err := SignWithSecret(claims, secret, HS256)
		require.NoError(t, err)

		// Should error - HMAC token requires VerifyWithSecret
		_, err = Verify(token, pubKey, DefaultVerifyOptions())
		assert.Error(t, err)
	})

	t.Run("RSA token with VerifyWithSecret", func(t *testing.T) {
		claims := NewClaims()
		claims.Subject = "user"
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		// Should error - RSA token requires Verify
		_, err = VerifyWithSecret(token, secret, DefaultVerifyOptions())
		assert.Error(t, err)
	})
}

func TestRSAPSSAlgorithm(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	claims := NewClaims()
	claims.Subject = "pss-user"
	claims.SetExpiration(time.Hour)

	opts := DefaultSignOptions()
	opts.UsePSS = true

	// Sign with PSS
	token, err := Sign(claims, privKey, PS256, opts)
	require.NoError(t, err)

	// Verify
	_, err = Verify(token, pubKey, DefaultVerifyOptions())
	require.NoError(t, err)
}

func TestAudienceValidationEdgeCases(t *testing.T) {
	privKey, pubKey := generateRSAKey(t)

	t.Run("No expected audience - just check exists", func(t *testing.T) {
		claims := NewClaims()
		claims.Audience = []string{"any-audience"}
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		opts := DefaultVerifyOptions()
		opts.Validation.ValidateAudience = true
		opts.Validation.ExpectedAudience = []string{} // Empty = just check exists

		_, err = Verify(token, pubKey, opts)
		require.NoError(t, err)
	})

	t.Run("Multiple expected audiences - one matches", func(t *testing.T) {
		claims := NewClaims()
		claims.Audience = []string{"api.example.com"}
		claims.SetExpiration(time.Hour)

		token, err := Sign(claims, privKey, RS256, DefaultSignOptions())
		require.NoError(t, err)

		opts := DefaultVerifyOptions()
		opts.Validation.ValidateAudience = true
		opts.Validation.ExpectedAudience = []string{"web.example.com", "api.example.com"}

		_, err = Verify(token, pubKey, opts)
		require.NoError(t, err)
	})
}

func TestEncodingErrors(t *testing.T) {
	// Test encodeSegment with un-marshalable type
	ch := make(chan int) // channels can't be marshaled to JSON
	_, err := encodeSegment(ch)
	assert.Error(t, err)

	// Test decodeSegment with invalid JSON
	invalidJSON := base64URLEncode([]byte("{invalid json}"))
	var target map[string]interface{}
	err = decodeSegment(invalidJSON, &target)
	assert.Error(t, err)
}

func TestHMACWithInvalidHash(t *testing.T) {
	// This tests the error path in signHMAC
	_, err := signHMAC([]byte("data"), []byte("secret"), 999) // Invalid hash algorithm
	assert.Error(t, err)
}

func TestUnsupportedAlgorithm(t *testing.T) {
	alg := Algorithm("UNSUPPORTED")

	err := alg.Validate()
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)

	_, err = alg.HashFunc()
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}
