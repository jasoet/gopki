package algo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDSACurveConstants(t *testing.T) {
	tests := []struct {
		name     string
		curve    ECDSACurve
		expected elliptic.Curve
	}{
		{"P224", P224, elliptic.P224()},
		{"P256", P256, elliptic.P256()},
		{"P384", P384, elliptic.P384()},
		{"P521", P521, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.curve.Curve()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestECDSACurve_InvalidCurve(t *testing.T) {
	// Test that invalid curve values default to P256
	invalidCurve := ECDSACurve(999)
	assert.Equal(t, elliptic.P256(), invalidCurve.Curve())
}

func TestGenerateECDSAKeyPair_ValidCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve ECDSACurve
	}{
		{"P224", P224},
		{"P256", P256},
		{"P384", P384},
		{"P521", P521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(tt.curve)

			assert.NoError(t, err)
			assert.NotNil(t, keyPair)
			if keyPair == nil {
				t.Fatal("keyPair is nil")
			}
			assert.NotNil(t, keyPair.PrivateKey)
			assert.NotNil(t, keyPair.PublicKey)

			// Verify curve matches request
			assert.Equal(t, tt.curve.Curve(), keyPair.PrivateKey.Curve)

			// Verify public key is derived from private key
			assert.Equal(t, &keyPair.PrivateKey.PublicKey, keyPair.PublicKey)

			// Verify key coordinates are on the curve
			assert.True(t, keyPair.PrivateKey.Curve.IsOnCurve(keyPair.PublicKey.X, keyPair.PublicKey.Y))
		})
	}
}

func TestECDSAKeyPair_PrivateKeyToPEM(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
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

	ecdsaKey, ok := parsedKey.(*ecdsa.PrivateKey)
	assert.True(t, ok)
	assert.Equal(t, keyPair.PrivateKey.Curve, ecdsaKey.Curve)
}

func TestECDSAKeyPair_PublicKeyToPEM(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
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

	ecdsaKey, ok := parsedKey.(*ecdsa.PublicKey)
	assert.True(t, ok)
	assert.Equal(t, keyPair.PublicKey.Curve, ecdsaKey.Curve)
}

func TestECDSAKeyPairFromPEM_Success(t *testing.T) {
	// Generate original key pair
	originalKeyPair, err := GenerateECDSAKeyPair(P256)
	assert.NoError(t, err)
	assert.NotNil(t, originalKeyPair)

	// Convert to PEM
	pemData, err := originalKeyPair.PrivateKeyToPEM()
	assert.NoError(t, err)

	// Reconstruct from PEM
	reconstructedKeyPair, err := ECDSAKeyPairFromPEM(pemData)
	assert.NoError(t, err)
	assert.NotNil(t, reconstructedKeyPair)

	// Verify the keys match
	assert.Equal(t, originalKeyPair.PrivateKey.Curve, reconstructedKeyPair.PrivateKey.Curve)
	assert.Equal(t, originalKeyPair.PrivateKey.D, reconstructedKeyPair.PrivateKey.D)
	assert.Equal(t, originalKeyPair.PublicKey.X, reconstructedKeyPair.PublicKey.X)
	assert.Equal(t, originalKeyPair.PublicKey.Y, reconstructedKeyPair.PublicKey.Y)
	assert.Equal(t, &reconstructedKeyPair.PrivateKey.PublicKey, reconstructedKeyPair.PublicKey)
}

func TestECDSAKeyPairFromPEM_InvalidPEM(t *testing.T) {
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
			name: "NotECDSAKey",
			pemData: func() []byte {
				// Create an RSA key PEM that's not ECDSA
				rsaKeyPair, _ := GenerateRSAKeyPair(KeySize2048)
				rsaPEM, _ := rsaKeyPair.PrivateKeyToPEM()
				return rsaPEM
			}(),
			errMsg: "private key is not an ECDSA key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := ECDSAKeyPairFromPEM(tt.pemData)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestECDSAKeyPair_PEMRoundTrip(t *testing.T) {
	// Test with different curves
	tests := []struct {
		name  string
		curve ECDSACurve
	}{
		{"P224", P224},
		{"P256", P256},
		{"P384", P384},
		{"P521", P521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate original key pair
			original, err := GenerateECDSAKeyPair(tt.curve)
			assert.NoError(t, err)
			assert.NotNil(t, original)

			// Convert to PEM and back
			privatePEM, err := original.PrivateKeyToPEM()
			assert.NoError(t, err)

			publicPEM, err := original.PublicKeyToPEM()
			assert.NoError(t, err)

			// Reconstruct from private key PEM
			reconstructed, err := ECDSAKeyPairFromPEM(privatePEM)
			assert.NoError(t, err)
			assert.NotNil(t, reconstructed)

			// Verify private keys match
			assert.Equal(t, original.PrivateKey.Curve, reconstructed.PrivateKey.Curve)
			assert.Equal(t, original.PrivateKey.D, reconstructed.PrivateKey.D)

			// Verify public keys match
			assert.Equal(t, original.PublicKey.X, reconstructed.PublicKey.X)
			assert.Equal(t, original.PublicKey.Y, reconstructed.PublicKey.Y)

			// Verify reconstructed public key PEM matches original
			reconstructedPublicPEM, err := reconstructed.PublicKeyToPEM()
			assert.NoError(t, err)
			assert.Equal(t, string(publicPEM), string(reconstructedPublicPEM))
		})
	}
}

func TestECDSAKeyPair_PEMFormat(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
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

func TestECDSAKeyPair_KeyValidation(t *testing.T) {
	curves := []ECDSACurve{P224, P256, P384, P521}

	for _, curve := range curves {
		t.Run(curve.Curve().Params().Name, func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(curve)
			assert.NoError(t, err)
			assert.NotNil(t, keyPair)

			// Verify the public key coordinates are on the curve
			assert.True(t, keyPair.PrivateKey.Curve.IsOnCurve(keyPair.PublicKey.X, keyPair.PublicKey.Y))

			// Verify curve matches expected
			assert.Equal(t, curve.Curve(), keyPair.PrivateKey.Curve)
			assert.Equal(t, curve.Curve(), keyPair.PublicKey.Curve)

			// Verify public key is derived from private key
			assert.Equal(t, &keyPair.PrivateKey.PublicKey, keyPair.PublicKey)
		})
	}
}

func TestECDSAKeyPair_CurveSecurityLevels(t *testing.T) {
	// Test that different curves generate keys with expected bit lengths
	tests := []struct {
		name         string
		curve        ECDSACurve
		expectedBits int
	}{
		{"P224", P224, 224},
		{"P256", P256, 256},
		{"P384", P384, 384},
		{"P521", P521, 521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(tt.curve)
			assert.NoError(t, err)
			assert.NotNil(t, keyPair)

			// Verify curve bit size matches expected
			assert.Equal(t, tt.expectedBits, keyPair.PrivateKey.Curve.Params().BitSize)
		})
	}
}

func BenchmarkGenerateECDSAKeyPair(b *testing.B) {
	tests := []struct {
		name  string
		curve ECDSACurve
	}{
		{"P224", P224},
		{"P256", P256},
		{"P384", P384},
		{"P521", P521},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := GenerateECDSAKeyPair(tt.curve)
				if err != nil {
					b.Fatalf("Key generation failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkECDSAKeyPair_PEMOperations(b *testing.B) {
	keyPair, err := GenerateECDSAKeyPair(P256)
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
	b.Run("ECDSAKeyPairFromPEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := ECDSAKeyPairFromPEM(pemData)
			if err != nil {
				b.Fatalf("PEM reconstruction failed: %v", err)
			}
		}
	})
}