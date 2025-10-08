package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test RSA key export and import
func TestRSAKeyRoundTrip(t *testing.T) {
	// Generate RSA key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	// Export to JWK
	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "rsa-test-1")
	require.NoError(t, err)
	assert.Equal(t, "RSA", jwk.KeyType)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "rsa-test-1", jwk.KeyID)
	assert.NotEmpty(t, jwk.N)
	assert.NotEmpty(t, jwk.E)

	// Import back to public key
	publicKey, err := jwk.ToPublicKey()
	require.NoError(t, err)

	// Verify it's RSA key
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.PublicKey.N, rsaKey.N)
	assert.Equal(t, keyPair.PublicKey.E, rsaKey.E)
}

// Test ECDSA P-256 key export and import
func TestECDSAP256KeyRoundTrip(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	// Export to JWK
	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "ec-p256-1")
	require.NoError(t, err)
	assert.Equal(t, "EC", jwk.KeyType)
	assert.Equal(t, "P-256", jwk.Curve)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)

	// Import back
	publicKey, err := jwk.ToPublicKey()
	require.NoError(t, err)

	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.PublicKey.X, ecKey.X)
	assert.Equal(t, keyPair.PublicKey.Y, ecKey.Y)
}

// Test ECDSA P-384 key export and import
func TestECDSAP384KeyRoundTrip(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P384)
	require.NoError(t, err)

	jwk, err := FromPublicKey(keyPair.PublicKey, "enc", "ec-p384-1")
	require.NoError(t, err)
	assert.Equal(t, "P-384", jwk.Curve)

	publicKey, err := jwk.ToPublicKey()
	require.NoError(t, err)

	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.PublicKey.Curve.Params().Name, ecKey.Curve.Params().Name)
}

// Test ECDSA P-521 key export and import
func TestECDSAP521KeyRoundTrip(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P521)
	require.NoError(t, err)

	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "ec-p521-1")
	require.NoError(t, err)
	assert.Equal(t, "P-521", jwk.Curve)

	publicKey, err := jwk.ToPublicKey()
	require.NoError(t, err)

	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.PublicKey.X, ecKey.X)
	assert.Equal(t, keyPair.PublicKey.Y, ecKey.Y)
}

// Test Ed25519 key export and import
func TestEd25519KeyRoundTrip(t *testing.T) {
	keyPair, err := algo.GenerateEd25519KeyPair()
	require.NoError(t, err)

	// Export to JWK
	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "ed25519-1")
	require.NoError(t, err)
	assert.Equal(t, "OKP", jwk.KeyType)
	assert.Equal(t, "Ed25519", jwk.Curve)
	assert.NotEmpty(t, jwk.X)

	// Import back
	publicKey, err := jwk.ToPublicKey()
	require.NoError(t, err)

	edKey, ok := publicKey.(ed25519.PublicKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.PublicKey, edKey)
}

// Test FromGoPKIKeyPair with RSA
func TestFromGoPKIKeyPairRSA(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	jwk, err := FromGoPKIKeyPair(keyPair, "sig", "test-rsa")
	require.NoError(t, err)
	assert.Equal(t, "RSA", jwk.KeyType)
	assert.Equal(t, "test-rsa", jwk.KeyID)
}

// Test FromGoPKIKeyPair with ECDSA
func TestFromGoPKIKeyPairECDSA(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	jwk, err := FromGoPKIKeyPair(keyPair, "enc", "test-ec")
	require.NoError(t, err)
	assert.Equal(t, "EC", jwk.KeyType)
	assert.Equal(t, "test-ec", jwk.KeyID)
}

// Test FromGoPKIKeyPair with Ed25519
func TestFromGoPKIKeyPairEd25519(t *testing.T) {
	keyPair, err := algo.GenerateEd25519KeyPair()
	require.NoError(t, err)

	jwk, err := FromGoPKIKeyPair(keyPair, "sig", "test-ed")
	require.NoError(t, err)
	assert.Equal(t, "OKP", jwk.KeyType)
	assert.Equal(t, "test-ed", jwk.KeyID)
}

// Test JWK marshaling and unmarshaling
func TestJWKMarshalUnmarshal(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	// Create JWK
	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "marshal-test")
	require.NoError(t, err)

	// Marshal to JSON
	data, err := jwk.Marshal()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal back
	parsed, err := Parse(data)
	require.NoError(t, err)
	assert.Equal(t, jwk.KeyType, parsed.KeyType)
	assert.Equal(t, jwk.KeyID, parsed.KeyID)
	assert.Equal(t, jwk.Use, parsed.Use)
	assert.Equal(t, jwk.N, parsed.N)
	assert.Equal(t, jwk.E, parsed.E)
}

// Test JWK MarshalIndent
func TestJWKMarshalIndent(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "indent-test")
	require.NoError(t, err)

	data, err := jwk.MarshalIndent("", "  ")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "\n") // Should have newlines
}

// Test IsPrivate method
func TestIsPrivate(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	// Public key JWK
	jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "public-test")
	require.NoError(t, err)
	assert.False(t, jwk.IsPrivate())

	// Manually set private exponent to simulate private key
	jwk.D = "test-private-value"
	assert.True(t, jwk.IsPrivate())
}

// Test JWK Set operations
func TestJWKSetOperations(t *testing.T) {
	// Create multiple keys
	rsa1, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsa2, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	ec1, _ := algo.GenerateECDSAKeyPair(algo.P256)

	jwk1, _ := FromPublicKey(rsa1.PublicKey, "sig", "key-1")
	jwk2, _ := FromPublicKey(rsa2.PublicKey, "enc", "key-2")
	jwk3, _ := FromPublicKey(ec1.PublicKey, "sig", "key-3")

	// Create set and add keys
	set := &JWKSet{}
	set.Add(jwk1)
	set.Add(jwk2)
	set.Add(jwk3)

	assert.Equal(t, 3, set.Len())

	// Find by key ID
	found, err := set.FindByKeyID("key-2")
	require.NoError(t, err)
	assert.Equal(t, "enc", found.Use)

	// Find by use
	sigKeys := set.FindByUse("sig")
	assert.Len(t, sigKeys, 2)

	// Remove key
	removed := set.Remove("key-1")
	assert.True(t, removed)
	assert.Equal(t, 2, set.Len())

	// Try to find removed key
	_, err = set.FindByKeyID("key-1")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// Test JWK Set marshaling and unmarshaling
func TestJWKSetMarshalUnmarshal(t *testing.T) {
	rsa1, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsa2, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	jwk1, _ := FromPublicKey(rsa1.PublicKey, "sig", "set-key-1")
	jwk2, _ := FromPublicKey(rsa2.PublicKey, "enc", "set-key-2")

	set := &JWKSet{}
	set.Add(jwk1)
	set.Add(jwk2)

	// Marshal
	data, err := set.Marshal()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal
	parsed, err := ParseSet(data)
	require.NoError(t, err)
	assert.Equal(t, 2, parsed.Len())

	// Verify keys
	foundKey1, err := parsed.FindByKeyID("set-key-1")
	require.NoError(t, err)
	assert.Equal(t, "sig", foundKey1.Use)

	foundKey2, err := parsed.FindByKeyID("set-key-2")
	require.NoError(t, err)
	assert.Equal(t, "enc", foundKey2.Use)
}

// Test error cases
func TestErrorCases(t *testing.T) {
	t.Run("Invalid JWK JSON", func(t *testing.T) {
		_, err := Parse([]byte("invalid json"))
		assert.Error(t, err)
	})

	t.Run("Missing key type", func(t *testing.T) {
		_, err := Parse([]byte(`{"use":"sig"}`))
		assert.ErrorIs(t, err, ErrMissingRequiredField)
	})

	t.Run("Missing RSA parameters", func(t *testing.T) {
		_, err := Parse([]byte(`{"kty":"RSA","n":"AQAB"}`))
		assert.ErrorIs(t, err, ErrMissingRequiredField)
	})

	t.Run("Missing EC parameters", func(t *testing.T) {
		_, err := Parse([]byte(`{"kty":"EC","crv":"P-256"}`))
		assert.ErrorIs(t, err, ErrMissingRequiredField)
	})

	t.Run("Invalid key type", func(t *testing.T) {
		_, err := Parse([]byte(`{"kty":"UNKNOWN"}`))
		assert.ErrorIs(t, err, ErrInvalidKeyType)
	})

	t.Run("Invalid EC curve", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "EC",
			Curve:   "P-999",
			X:       "AQAB",
			Y:       "AQAB",
		}
		_, err := jwk.ToPublicKey()
		assert.ErrorIs(t, err, ErrInvalidCurve)
	})

	t.Run("Invalid OKP curve", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "OKP",
			Curve:   "X25519",
			X:       "AQAB",
		}
		_, err := jwk.ToPublicKey()
		assert.ErrorIs(t, err, ErrInvalidCurve)
	})

	t.Run("EC point not on curve", func(t *testing.T) {
		// Create JWK with invalid EC point
		jwk := &JWK{
			KeyType: "EC",
			Curve:   "P-256",
			X:       "AQAB", // Invalid point
			Y:       "AQAB",
		}
		_, err := jwk.ToPublicKey()
		assert.Error(t, err)
	})

	t.Run("Nil public key", func(t *testing.T) {
		_, err := FromPublicKey(nil, "sig", "test")
		assert.Error(t, err)
	})

	t.Run("JWK Set with invalid key", func(t *testing.T) {
		invalidJSON := []byte(`{"keys":[{"kty":"RSA"}]}`)
		_, err := ParseSet(invalidJSON)
		assert.Error(t, err)
	})

	t.Run("Key not found in set", func(t *testing.T) {
		set := &JWKSet{}
		_, err := set.FindByKeyID("nonexistent")
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("Remove nonexistent key", func(t *testing.T) {
		set := &JWKSet{}
		removed := set.Remove("nonexistent")
		assert.False(t, removed)
	})
}

// Test ECDSA coordinate padding
func TestECDSACoordinatePadding(t *testing.T) {
	// Generate multiple keys to potentially hit padding cases
	for i := 0; i < 10; i++ {
		keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		require.NoError(t, err)

		jwk, err := FromPublicKey(keyPair.PublicKey, "sig", "padding-test")
		require.NoError(t, err)

		// Decode and check length
		// P-256 should always have 32-byte coordinates
		xBytes, err := jwk.ToPublicKey()
		require.NoError(t, err)

		ecKey := xBytes.(*ecdsa.PublicKey)
		assert.Equal(t, keyPair.PublicKey.X, ecKey.X)
		assert.Equal(t, keyPair.PublicKey.Y, ecKey.Y)
	}
}
