package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignRaw_ECDSA_P256(t *testing.T) {
	// Generate ECDSA P-256 key pair
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data for signing")
	opts := DefaultRawSignOptions()

	// Test signing
	signature, err := SignRaw(data, keyPair, opts)
	require.NoError(t, err)
	assert.Equal(t, 64, len(signature), "ECDSA P-256 signature should be 64 bytes")

	// Test verification
	valid, err := VerifyRaw(data, signature, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")

	// Test with tampered data
	tamperedData := []byte("tampered data")
	valid, err = VerifyRaw(tamperedData, signature, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.False(t, valid, "Signature should be invalid for tampered data")
}

func TestSignRaw_ECDSA_P384(t *testing.T) {
	// Generate ECDSA P-384 key pair
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P384)
	require.NoError(t, err)

	data := []byte("test data for P-384")
	opts := DefaultRawSignOptions()
	opts.HashAlgorithm = crypto.SHA384

	// Test signing
	signature, err := SignRaw(data, keyPair, opts)
	require.NoError(t, err)
	assert.Equal(t, 96, len(signature), "ECDSA P-384 signature should be 96 bytes")

	// Test verification
	valid, err := VerifyRaw(data, signature, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")
}

func TestSignRaw_Ed25519(t *testing.T) {
	// Generate Ed25519 key pair
	keyPair, err := algo.GenerateEd25519KeyPair()
	require.NoError(t, err)

	data := []byte("test data for Ed25519")
	opts := DefaultRawSignOptions()

	// Test signing
	signature, err := SignRaw(data, keyPair, opts)
	require.NoError(t, err)
	assert.Equal(t, ed25519.SignatureSize, len(signature), "Ed25519 signature should be 64 bytes")

	// Test verification
	valid, err := VerifyRaw(data, signature, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")
}

func TestSignRaw_RSA(t *testing.T) {
	// Generate RSA key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	data := []byte("test data for RSA")
	opts := DefaultRawSignOptions()

	// Test signing
	signature, err := SignRaw(data, keyPair, opts)
	require.NoError(t, err)
	assert.Equal(t, 256, len(signature), "RSA-2048 signature should be 256 bytes")

	// Test verification
	valid, err := VerifyRaw(data, signature, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")
}

func TestSignRawString_Base64(t *testing.T) {
	// Generate key pair
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data for base64 encoding")
	opts := DefaultRawSignOptions()

	// Test string signing (returns base64)
	signatureBase64, err := SignRawString(data, keyPair, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, signatureBase64)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(signatureBase64)
	require.NoError(t, err)
	assert.Equal(t, 64, len(decoded))

	// Test verification with string
	valid, err := VerifyRawString(data, signatureBase64, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")
}

func TestSignRaw_WithBase64Option(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data")
	opts := DefaultRawSignOptions()
	opts.Base64Encode = true

	// Sign with base64 encoding
	signature, err := SignRaw(data, keyPair, opts)
	require.NoError(t, err)

	// Should be base64 string
	signatureStr := string(signature)
	decoded, err := base64.StdEncoding.DecodeString(signatureStr)
	require.NoError(t, err)
	assert.Equal(t, 64, len(decoded))

	// Verify with base64
	valid, err := VerifyRaw(data, signature, keyPair.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyRaw_InvalidSignatureLength(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data")
	opts := DefaultRawSignOptions()

	// Test with invalid signature length
	invalidSignature := make([]byte, 32) // Should be 64 for P-256
	valid, err := VerifyRaw(data, invalidSignature, keyPair.PublicKey, opts)
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestVerifyRawWithPEM(t *testing.T) {
	// Generate key pair
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	// Get PEM-encoded public key
	publicKeyPEM, err := keyPair.PublicKeyToPEM()
	require.NoError(t, err)

	data := []byte("test data for PEM verification")
	opts := DefaultRawSignOptions()

	// Sign
	signature, err := SignRaw(data, keyPair, opts)
	require.NoError(t, err)

	// Verify with PEM
	valid, err := VerifyRawWithPEM(data, signature, publicKeyPEM, opts)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestGetRawSignatureSize(t *testing.T) {
	tests := []struct {
		name         string
		generateKey  func() (crypto.PublicKey, error)
		expectedSize int
	}{
		{
			name: "ECDSA P-256",
			generateKey: func() (crypto.PublicKey, error) {
				kp, err := algo.GenerateECDSAKeyPair(algo.P256)
				return kp.PublicKey, err
			},
			expectedSize: 64,
		},
		{
			name: "ECDSA P-384",
			generateKey: func() (crypto.PublicKey, error) {
				kp, err := algo.GenerateECDSAKeyPair(algo.P384)
				return kp.PublicKey, err
			},
			expectedSize: 96,
		},
		{
			name: "Ed25519",
			generateKey: func() (crypto.PublicKey, error) {
				kp, err := algo.GenerateEd25519KeyPair()
				return kp.PublicKey, err
			},
			expectedSize: 64,
		},
		{
			name: "RSA-2048",
			generateKey: func() (crypto.PublicKey, error) {
				kp, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
				return kp.PublicKey, err
			},
			expectedSize: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, err := tt.generateKey()
			require.NoError(t, err)

			size, err := GetRawSignatureSize(publicKey)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}


func TestSignRaw_DifferentHashAlgorithms(t *testing.T) {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data")

	tests := []struct {
		name     string
		hashAlgo crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultRawSignOptions()
			opts.HashAlgorithm = tt.hashAlgo

			signature, err := SignRaw(data, keyPair, opts)
			require.NoError(t, err)

			valid, err := VerifyRaw(data, signature, keyPair.PublicKey, opts)
			require.NoError(t, err)
			assert.True(t, valid)
		})
	}
}

func TestSignRaw_MultipleRuns(t *testing.T) {
	// Test that signing the same data produces different signatures due to randomness
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data")
	opts := DefaultRawSignOptions()

	// Sign multiple times
	signatures := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		sig, err := SignRaw(data, keyPair, opts)
		require.NoError(t, err)
		signatures[i] = sig

		// Verify each signature
		valid, err := VerifyRaw(data, sig, keyPair.PublicKey, opts)
		require.NoError(t, err)
		assert.True(t, valid)
	}

	// ECDSA signatures should be different due to random k value
	// (This is a property of ECDSA, not a bug)
	allSame := true
	for i := 1; i < len(signatures); i++ {
		if !assert.ObjectsAreEqual(signatures[0], signatures[i]) {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "ECDSA signatures should vary due to randomness")
}

func TestVerifyRaw_WrongKey(t *testing.T) {
	// Generate two different key pairs
	keyPair1, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	keyPair2, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	data := []byte("test data")
	opts := DefaultRawSignOptions()

	// Sign with key 1
	signature, err := SignRaw(data, keyPair1, opts)
	require.NoError(t, err)

	// Try to verify with key 2 (should fail)
	valid, err := VerifyRaw(data, signature, keyPair2.PublicKey, opts)
	require.NoError(t, err)
	assert.False(t, valid, "Signature should not verify with wrong key")
}

// Benchmark tests
func BenchmarkSignRaw_ECDSA_P256(b *testing.B) {
	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
	data := []byte("benchmark data")
	opts := DefaultRawSignOptions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignRaw(data, keyPair, opts)
	}
}

func BenchmarkVerifyRaw_ECDSA_P256(b *testing.B) {
	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
	data := []byte("benchmark data")
	opts := DefaultRawSignOptions()
	signature, _ := SignRaw(data, keyPair, opts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyRaw(data, signature, keyPair.PublicKey, opts)
	}
}

func BenchmarkSignRaw_Ed25519(b *testing.B) {
	keyPair, _ := algo.GenerateEd25519KeyPair()
	data := []byte("benchmark data")
	opts := DefaultRawSignOptions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignRaw(data, keyPair, opts)
	}
}

func BenchmarkSignRaw_RSA2048(b *testing.B) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	data := []byte("benchmark data")
	opts := DefaultRawSignOptions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignRaw(data, keyPair, opts)
	}
}

// Test internal functions
func Test_signECDSARaw(t *testing.T) {
	// Generate a raw ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data")
	hash := sha256.Sum256(data)
	digest := hash[:]

	signature, err := signECDSARaw(privateKey, digest)
	require.NoError(t, err)
	assert.Equal(t, 64, len(signature))
}

func Test_verifyECDSARaw(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data")
	hash := sha256.Sum256(data)
	digest := hash[:]

	// Sign
	signature, err := signECDSARaw(privateKey, digest)
	require.NoError(t, err)

	// Verify
	valid, err := verifyECDSARaw(&privateKey.PublicKey, digest, signature)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify with tampered data
	tamperedData := []byte("tampered data")
	tamperedHash := sha256.Sum256(tamperedData)
	tamperedDigest := tamperedHash[:]
	valid, err = verifyECDSARaw(&privateKey.PublicKey, tamperedDigest, signature)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestDefaultRawSignOptions(t *testing.T) {
	opts := DefaultRawSignOptions()
	assert.Equal(t, crypto.SHA256, opts.HashAlgorithm)
	assert.False(t, opts.Base64Encode)
}
