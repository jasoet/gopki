package algo

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEd25519Config(t *testing.T) {
	// Test that Ed25519Config is just a string type
	config := Ed25519Config("default")
	assert.Equal(t, "default", string(config))
}

func TestGenerateEd25519KeyPair_Success(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()

	assert.NoError(t, err)
	assert.NotNil(t, keyPair)
	assert.NotNil(t, keyPair.PrivateKey)
	assert.NotNil(t, keyPair.PublicKey)

	// Verify Ed25519 key lengths
	assert.Equal(t, ed25519.PrivateKeySize, len(keyPair.PrivateKey))
	assert.Equal(t, ed25519.PublicKeySize, len(keyPair.PublicKey))

	// Verify public key is derived from private key
	expectedPublicKey := keyPair.PrivateKey.Public().(ed25519.PublicKey)
	assert.Equal(t, expectedPublicKey, keyPair.PublicKey)
}

func TestGenerateEd25519KeyPair_MultipleGenerations(t *testing.T) {
	// Generate multiple key pairs to ensure randomness
	keyPairs := make([]*Ed25519KeyPair, 5)

	for i := 0; i < 5; i++ {
		keyPair, err := GenerateEd25519KeyPair()
		assert.NoError(t, err)
		assert.NotNil(t, keyPair)
		keyPairs[i] = keyPair
	}

	// Verify all keys are different
	for i := 0; i < len(keyPairs); i++ {
		for j := i + 1; j < len(keyPairs); j++ {
			assert.NotEqual(t, keyPairs[i].PrivateKey, keyPairs[j].PrivateKey, "Private keys should be different")
			assert.NotEqual(t, keyPairs[i].PublicKey, keyPairs[j].PublicKey, "Public keys should be different")
		}
	}
}

func TestEd25519KeyPair_PrivateKeyToPEM(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)

	pemData, err := keyPair.PrivateKeyToPEM()
	assert.NoError(t, err)
	assert.NotEmpty(t, pemData)

	// Verify PEM format
	block, _ := pem.Decode(pemData)
	assert.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	// Verify we can parse the PEM back to a private key
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)

	ed25519Key, ok := parsedKey.(ed25519.PrivateKey)
	assert.True(t, ok)
	assert.Equal(t, len(keyPair.PrivateKey), len(ed25519Key))
	assert.Equal(t, keyPair.PrivateKey, ed25519Key)
}

func TestEd25519KeyPair_PublicKeyToPEM(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)

	pemData, err := keyPair.PublicKeyToPEM()
	assert.NoError(t, err)
	assert.NotEmpty(t, pemData)

	// Verify PEM format
	block, _ := pem.Decode(pemData)
	assert.NotNil(t, block)
	assert.Equal(t, "PUBLIC KEY", block.Type)

	// Verify we can parse the PEM back to a public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err)

	ed25519Key, ok := parsedKey.(ed25519.PublicKey)
	assert.True(t, ok)
	assert.Equal(t, len(keyPair.PublicKey), len(ed25519Key))
	assert.Equal(t, keyPair.PublicKey, ed25519Key)
}

func TestEd25519KeyPairFromPEM_Success(t *testing.T) {
	// Generate original key pair
	originalKeyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, originalKeyPair)

	// Convert to PEM
	pemData, err := originalKeyPair.PrivateKeyToPEM()
	assert.NoError(t, err)

	// Reconstruct from PEM
	reconstructedKeyPair, err := Ed25519KeyPairFromPEM(pemData)
	assert.NoError(t, err)
	assert.NotNil(t, reconstructedKeyPair)

	// Verify the keys match exactly
	assert.Equal(t, originalKeyPair.PrivateKey, reconstructedKeyPair.PrivateKey)
	assert.Equal(t, originalKeyPair.PublicKey, reconstructedKeyPair.PublicKey)

	// Verify public key is derived from private key
	expectedPublicKey := reconstructedKeyPair.PrivateKey.Public().(ed25519.PublicKey)
	assert.Equal(t, expectedPublicKey, reconstructedKeyPair.PublicKey)
}

func TestEd25519KeyPairFromPEM_InvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
		errMsg  string
	}{
		{
			name:    "NotPEM",
			pemData: []byte("not a pem file"),
			errMsg:  "failed to decode PEM block",
		},
		{
			name: "InvalidPEMContent",
			pemData: []byte(`-----BEGIN PRIVATE KEY-----
invalid base64 content
-----END PRIVATE KEY-----`),
			errMsg: "failed to parse private key",
		},
		{
			name: "NotEd25519Key_RSA",
			pemData: func() []byte {
				// Create an RSA key PEM that's not Ed25519
				rsaKeyPair, _ := GenerateRSAKeyPair(KeySize2048)
				rsaPEM, _ := rsaKeyPair.PrivateKeyToPEM()
				return rsaPEM
			}(),
			errMsg: "private key is not an Ed25519 key",
		},
		{
			name: "NotEd25519Key_ECDSA",
			pemData: func() []byte {
				// Create an ECDSA key PEM that's not Ed25519
				ecdsaKeyPair, _ := GenerateECDSAKeyPair(P256)
				ecdsaPEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
				return ecdsaPEM
			}(),
			errMsg: "private key is not an Ed25519 key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := Ed25519KeyPairFromPEM(tt.pemData)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestEd25519KeyPair_PEMRoundTrip(t *testing.T) {
	// Generate original key pair
	original, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, original)

	// Convert to PEM and back
	privatePEM, err := original.PrivateKeyToPEM()
	assert.NoError(t, err)

	publicPEM, err := original.PublicKeyToPEM()
	assert.NoError(t, err)

	// Reconstruct from private key PEM
	reconstructed, err := Ed25519KeyPairFromPEM(privatePEM)
	assert.NoError(t, err)
	assert.NotNil(t, reconstructed)

	// Verify private keys match exactly
	assert.Equal(t, original.PrivateKey, reconstructed.PrivateKey)

	// Verify public keys match exactly
	assert.Equal(t, original.PublicKey, reconstructed.PublicKey)

	// Verify reconstructed public key PEM matches original
	reconstructedPublicPEM, err := reconstructed.PublicKeyToPEM()
	assert.NoError(t, err)
	assert.Equal(t, string(publicPEM), string(reconstructedPublicPEM))
}

func TestEd25519KeyPair_PEMFormat(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)

	// Test private key PEM format
	privatePEM, err := keyPair.PrivateKeyToPEM()
	assert.NoError(t, err)

	privateStr := string(privatePEM)
	assert.True(t, strings.HasPrefix(privateStr, "-----BEGIN PRIVATE KEY-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(privateStr), "-----END PRIVATE KEY-----"))

	// Test public key PEM format
	publicPEM, err := keyPair.PublicKeyToPEM()
	assert.NoError(t, err)

	publicStr := string(publicPEM)
	assert.True(t, strings.HasPrefix(publicStr, "-----BEGIN PUBLIC KEY-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(publicStr), "-----END PUBLIC KEY-----"))
}

func TestEd25519KeyPair_KeySizes(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)

	// Verify Ed25519 standard key sizes
	assert.Equal(t, ed25519.PrivateKeySize, len(keyPair.PrivateKey), "Ed25519 private key should be 64 bytes")
	assert.Equal(t, ed25519.PublicKeySize, len(keyPair.PublicKey), "Ed25519 public key should be 32 bytes")

	// Verify constants match expected values
	assert.Equal(t, 64, ed25519.PrivateKeySize)
	assert.Equal(t, 32, ed25519.PublicKeySize)
}

func TestEd25519KeyPair_PublicKeyDerivation(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)

	// Verify public key can be derived from private key
	derivedPublicKey := keyPair.PrivateKey.Public().(ed25519.PublicKey)
	assert.Equal(t, keyPair.PublicKey, derivedPublicKey)

	// Verify it's the same reference in our structure
	assert.Equal(t, keyPair.PublicKey, derivedPublicKey)
}

func TestEd25519KeyPair_CryptographicProperties(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)

	// Test basic signing/verification to ensure keys are cryptographically valid
	message := []byte("test message for Ed25519 signature verification")

	signature := ed25519.Sign(keyPair.PrivateKey, message)
	assert.NotNil(t, signature)
	assert.Equal(t, ed25519.SignatureSize, len(signature), "Ed25519 signature should be 64 bytes")

	// Verify signature with correct public key
	valid := ed25519.Verify(keyPair.PublicKey, message, signature)
	assert.True(t, valid, "Signature should be valid with correct public key")

	// Generate another key pair to test with wrong public key
	wrongKeyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Verify signature fails with wrong public key
	invalidVerification := ed25519.Verify(wrongKeyPair.PublicKey, message, signature)
	assert.False(t, invalidVerification, "Signature should be invalid with wrong public key")
}

func TestEd25519KeyPair_MultiplePEMRoundTrips(t *testing.T) {
	// Test multiple round trips to ensure consistency
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("RoundTrip_%d", i+1), func(t *testing.T) {
			// Generate original key pair
			original, err := GenerateEd25519KeyPair()
			assert.NoError(t, err)

			// First round trip
			pemData1, err := original.PrivateKeyToPEM()
			assert.NoError(t, err)

			reconstructed1, err := Ed25519KeyPairFromPEM(pemData1)
			assert.NoError(t, err)

			// Second round trip
			pemData2, err := reconstructed1.PrivateKeyToPEM()
			assert.NoError(t, err)

			reconstructed2, err := Ed25519KeyPairFromPEM(pemData2)
			assert.NoError(t, err)

			// All should be identical
			assert.Equal(t, original.PrivateKey, reconstructed1.PrivateKey)
			assert.Equal(t, original.PrivateKey, reconstructed2.PrivateKey)
			assert.Equal(t, original.PublicKey, reconstructed1.PublicKey)
			assert.Equal(t, original.PublicKey, reconstructed2.PublicKey)
			assert.Equal(t, string(pemData1), string(pemData2))
		})
	}
}

func BenchmarkGenerateEd25519KeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateEd25519KeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

func BenchmarkEd25519KeyPair_PEMOperations(b *testing.B) {
	keyPair, err := GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	b.Run("PrivateKeyToPEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := keyPair.PrivateKeyToPEM()
			if err != nil {
				b.Fatalf("PEM conversion failed: %v", err)
			}
		}
	})

	b.Run("PublicKeyToPEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := keyPair.PublicKeyToPEM()
			if err != nil {
				b.Fatalf("PEM conversion failed: %v", err)
			}
		}
	})

	pemData, _ := keyPair.PrivateKeyToPEM()
	b.Run("Ed25519KeyPairFromPEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := Ed25519KeyPairFromPEM(pemData)
			if err != nil {
				b.Fatalf("PEM reconstruction failed: %v", err)
			}
		}
	})
}

func BenchmarkEd25519_SignVerify(b *testing.B) {
	keyPair, err := GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	message := []byte("benchmark message for Ed25519 signature performance testing")

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signature := ed25519.Sign(keyPair.PrivateKey, message)
			if len(signature) != ed25519.SignatureSize {
				b.Fatalf("Invalid signature size: %d", len(signature))
			}
		}
	})

	signature := ed25519.Sign(keyPair.PrivateKey, message)
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			valid := ed25519.Verify(keyPair.PublicKey, message, signature)
			if !valid {
				b.Fatalf("Signature verification failed")
			}
		}
	})
}