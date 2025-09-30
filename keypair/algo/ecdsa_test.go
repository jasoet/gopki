package algo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/jasoet/gopki/keypair/format"

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

// DER Format Tests

func TestECDSAKeyPair_PrivateKeyToDER(t *testing.T) {
	curves := []ECDSACurve{P224, P256, P384, P521}

	for _, curve := range curves {
		t.Run(fmt.Sprintf("%s", curve.Curve().Params().Name), func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(curve)
			assert.NoError(t, err)

			derData, err := keyPair.PrivateKeyToDER()
			assert.NoError(t, err)
			assert.NotEmpty(t, derData)

			// Verify we can parse the DER back to a private key
			parsedKey, err := x509.ParsePKCS8PrivateKey(derData)
			assert.NoError(t, err)

			ecdsaKey, ok := parsedKey.(*ecdsa.PrivateKey)
			assert.True(t, ok, "Parsed key should be ECDSA")
			assert.Equal(t, keyPair.PrivateKey.Curve, ecdsaKey.Curve)

			// Verify DER is more compact than PEM
			pemData, err := keyPair.PrivateKeyToPEM()
			assert.NoError(t, err)
			assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")
		})
	}
}

func TestECDSAKeyPair_PublicKeyToDER(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
	assert.NoError(t, err)

	derData, err := keyPair.PublicKeyToDER()
	assert.NoError(t, err)
	assert.NotEmpty(t, derData)

	// Verify we can parse the DER back to a public key
	parsedKey, err := x509.ParsePKIXPublicKey(derData)
	assert.NoError(t, err)

	ecdsaKey, ok := parsedKey.(*ecdsa.PublicKey)
	assert.True(t, ok, "Parsed key should be ECDSA")
	assert.Equal(t, keyPair.PublicKey.Curve, ecdsaKey.Curve)

	// Verify DER is more compact than PEM
	pemData, err := keyPair.PublicKeyToPEM()
	assert.NoError(t, err)
	assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")
}

func TestECDSAKeyPairFromDER_Success(t *testing.T) {
	curves := []ECDSACurve{P224, P256, P384, P521}

	for _, curve := range curves {
		t.Run(fmt.Sprintf("%s", curve.Curve().Params().Name), func(t *testing.T) {
			// Generate original key pair
			originalKeyPair, err := GenerateECDSAKeyPair(curve)
			assert.NoError(t, err)

			// Convert to DER
			derData, err := originalKeyPair.PrivateKeyToDER()
			assert.NoError(t, err)

			// Reconstruct from DER
			reconstructedKeyPair, err := ECDSAKeyPairFromDER(derData)
			assert.NoError(t, err)
			assert.NotNil(t, reconstructedKeyPair)

			// Verify the keys match
			assert.Equal(t, originalKeyPair.PrivateKey.Curve, reconstructedKeyPair.PrivateKey.Curve)
			assert.Equal(t, originalKeyPair.PrivateKey.D, reconstructedKeyPair.PrivateKey.D)
			assert.Equal(t, originalKeyPair.PublicKey.X, reconstructedKeyPair.PublicKey.X)
			assert.Equal(t, originalKeyPair.PublicKey.Y, reconstructedKeyPair.PublicKey.Y)
			assert.Equal(t, &reconstructedKeyPair.PrivateKey.PublicKey, reconstructedKeyPair.PublicKey)

			// Verify key is on curve
			assert.True(t, reconstructedKeyPair.PrivateKey.Curve.IsOnCurve(reconstructedKeyPair.PublicKey.X, reconstructedKeyPair.PublicKey.Y))
		})
	}
}

func TestECDSAKeyPairFromDER_InvalidDER(t *testing.T) {
	tests := []struct {
		name    string
		derData []byte
		errMsg  string
	}{
		{
			name:    "InvalidDERData",
			derData: []byte("invalid der data"),
			errMsg:  "failed to parse DER private key",
		},
		{
			name:    "EmptyData",
			derData: []byte{},
			errMsg:  "failed to parse DER private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := ECDSAKeyPairFromDER(tt.derData)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestECDSAKeyPair_DERRoundTrip(t *testing.T) {
	curves := []ECDSACurve{P224, P256, P384, P521}

	for _, curve := range curves {
		t.Run(fmt.Sprintf("%s", curve.Curve().Params().Name), func(t *testing.T) {
			// Generate original key pair
			original, err := GenerateECDSAKeyPair(curve)
			assert.NoError(t, err)

			// Convert to DER and back
			privateDER, err := original.PrivateKeyToDER()
			assert.NoError(t, err)

			publicDER, err := original.PublicKeyToDER()
			assert.NoError(t, err)

			// Reconstruct from private key DER
			reconstructed, err := ECDSAKeyPairFromDER(privateDER)
			assert.NoError(t, err)

			// Verify private keys match
			assert.Equal(t, original.PrivateKey.Curve, reconstructed.PrivateKey.Curve)
			assert.Equal(t, original.PrivateKey.D, reconstructed.PrivateKey.D)

			// Verify public keys match
			assert.Equal(t, original.PublicKey.X, reconstructed.PublicKey.X)
			assert.Equal(t, original.PublicKey.Y, reconstructed.PublicKey.Y)

			// Verify reconstructed public key DER matches original
			reconstructedPublicDER, err := reconstructed.PublicKeyToDER()
			assert.NoError(t, err)
			assert.Equal(t, publicDER, reconstructedPublicDER)
		})
	}
}

// SSH Format Tests

func TestECDSAKeyPair_PublicKeyToSSH(t *testing.T) {
	// P224 is not supported by SSH, only test P256, P384, P521
	curves := []ECDSACurve{P256, P384, P521}

	for _, curve := range curves {
		t.Run(fmt.Sprintf("%s", curve.Curve().Params().Name), func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(curve)
			assert.NoError(t, err)

			// Test with comment
			sshData, err := keyPair.PublicKeyToSSH("user@example.com")
			assert.NoError(t, err)
			assert.NotEmpty(t, sshData)

			// Verify SSH format starts with ECDSA prefix (format varies by curve)
			assert.True(t, strings.HasPrefix(string(sshData), "ecdsa-sha2-"), "SSH key should start with ecdsa-sha2- prefix")
			assert.Contains(t, string(sshData), "user@example.com", "SSH key should contain comment")
			assert.Equal(t, 3, len(strings.Fields(string(sshData))), "SSH key should have 3 parts")

			// Test without comment
			sshDataNoComment, err := keyPair.PublicKeyToSSH("")
			assert.NoError(t, err)
			assert.Equal(t, 2, len(strings.Fields(string(sshDataNoComment))), "SSH key without comment should have 2 parts")
			assert.True(t, strings.HasPrefix(string(sshDataNoComment), "ecdsa-sha2-"))
		})
	}
}

func TestECDSAKeyPair_PublicKeyToSSH_UnsupportedCurve(t *testing.T) {
	// P224 is not supported by SSH
	keyPair, err := GenerateECDSAKeyPair(P224)
	assert.NoError(t, err)

	_, err = keyPair.PublicKeyToSSH("user@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only P-256, P-384 and P-521 EC keys are supported")
}

func TestECDSAKeyPair_PrivateKeyToSSH(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
	assert.NoError(t, err)

	// Test unencrypted SSH private key
	sshData, err := keyPair.PrivateKeyToSSH("test-key", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, sshData)
	assert.Contains(t, sshData, "-----BEGIN OPENSSH PRIVATE KEY-----")
	assert.Contains(t, sshData, "-----END OPENSSH PRIVATE KEY-----")

	// Test encrypted SSH private key
	passphrase := "test-passphrase-123"
	sshEncrypted, err := keyPair.PrivateKeyToSSH("encrypted-key", passphrase)
	assert.NoError(t, err)
	assert.NotEmpty(t, sshEncrypted)
	assert.Contains(t, sshEncrypted, "-----BEGIN OPENSSH PRIVATE KEY-----")
	assert.True(t, len(sshEncrypted) > len(sshData), "Encrypted key should be larger")
}

func TestECDSAKeyPairFromSSH_Success(t *testing.T) {
	// P224 is not supported by SSH, only test P256, P384, P521
	curves := []ECDSACurve{P256, P384, P521}

	for _, curve := range curves {
		t.Run(fmt.Sprintf("%s", curve.Curve().Params().Name), func(t *testing.T) {
			// Generate original key pair
			originalKeyPair, err := GenerateECDSAKeyPair(curve)
			assert.NoError(t, err)

			// Test unencrypted SSH round-trip
			sshData, err := originalKeyPair.PrivateKeyToSSH("test-key", "")
			assert.NoError(t, err)

			reconstructed, err := ECDSAKeyPairFromSSH(sshData, "")
			assert.NoError(t, err)
			assert.NotNil(t, reconstructed)
			assert.Equal(t, originalKeyPair.PrivateKey.Curve, reconstructed.PrivateKey.Curve)

			// Test encrypted SSH round-trip
			passphrase := "test-passphrase-123"
			sshEncrypted, err := originalKeyPair.PrivateKeyToSSH("encrypted-key", passphrase)
			assert.NoError(t, err)

			reconstructedEncrypted, err := ECDSAKeyPairFromSSH(sshEncrypted, passphrase)
			assert.NoError(t, err)
			assert.NotNil(t, reconstructedEncrypted)
			assert.Equal(t, originalKeyPair.PrivateKey.Curve, reconstructedEncrypted.PrivateKey.Curve)
		})
	}
}

func TestECDSAKeyPairFromSSH_UnsupportedCurve(t *testing.T) {
	// P224 is not supported by SSH
	keyPair, err := GenerateECDSAKeyPair(P224)
	assert.NoError(t, err)

	_, err = keyPair.PrivateKeyToSSH("test-key", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unhandled elliptic curve P-224")
}

func TestECDSAKeyPairFromSSH_InvalidSSH(t *testing.T) {
	tests := []struct {
		name       string
		sshData    string
		passphrase string
		errMsg     string
	}{
		{
			name:       "InvalidSSHData",
			sshData:    "invalid ssh data",
			passphrase: "",
			errMsg:     "failed to parse SSH private key",
		},
		{
			name: "WrongPassphrase",
			sshData: func() string {
				keyPair, _ := GenerateECDSAKeyPair(P256)
				sshData, _ := keyPair.PrivateKeyToSSH("test", "correct-passphrase")
				return string(sshData)
			}(),
			passphrase: "wrong-passphrase",
			errMsg:     "failed to parse SSH private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := ECDSAKeyPairFromSSH(format.SSH(tt.sshData), tt.passphrase)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestECDSAKeyPair_SSHRoundTrip(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
	assert.NoError(t, err)

	// Test unencrypted round-trip
	sshPrivate, err := keyPair.PrivateKeyToSSH("test-key", "")
	assert.NoError(t, err)

	sshPublic, err := keyPair.PublicKeyToSSH("test@example.com")
	assert.NoError(t, err)

	// Reconstruct from SSH private key
	reconstructed, err := ECDSAKeyPairFromSSH(sshPrivate, "")
	assert.NoError(t, err)

	// Verify keys match
	assert.Equal(t, keyPair.PrivateKey.Curve, reconstructed.PrivateKey.Curve)
	assert.Equal(t, keyPair.PrivateKey.D, reconstructed.PrivateKey.D)

	// Verify public key can be reconstructed correctly
	reconstructedPublic, err := reconstructed.PublicKeyToSSH("test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, sshPublic, reconstructedPublic)
}

// Cross-Format Tests

func TestECDSAKeyPair_CrossFormatCompatibility(t *testing.T) {
	// Generate original key pair
	original, err := GenerateECDSAKeyPair(P256)
	assert.NoError(t, err)

	// Test PEM -> DER -> SSH -> PEM conversion chain
	t.Run("PEM->DER->SSH->PEM", func(t *testing.T) {
		// PEM to DER
		pemData, err := original.PrivateKeyToPEM()
		assert.NoError(t, err)

		keyFromPEM, err := ECDSAKeyPairFromPEM(pemData)
		assert.NoError(t, err)

		derData, err := keyFromPEM.PrivateKeyToDER()
		assert.NoError(t, err)

		// DER to SSH
		keyFromDER, err := ECDSAKeyPairFromDER(derData)
		assert.NoError(t, err)

		sshData, err := keyFromDER.PrivateKeyToSSH("test", "")
		assert.NoError(t, err)

		// SSH back to PEM
		keyFromSSH, err := ECDSAKeyPairFromSSH(sshData, "")
		assert.NoError(t, err)

		finalPEM, err := keyFromSSH.PrivateKeyToPEM()
		assert.NoError(t, err)

		// Verify final result matches original
		finalKey, err := ECDSAKeyPairFromPEM(finalPEM)
		assert.NoError(t, err)
		assert.Equal(t, original.PrivateKey.Curve, finalKey.PrivateKey.Curve)
		assert.Equal(t, original.PrivateKey.D, finalKey.PrivateKey.D)
	})
}

// Enhanced Benchmarks

func BenchmarkECDSAKeyPair_AllFormats(b *testing.B) {
	keyPair, err := GenerateECDSAKeyPair(P256)
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	// DER operations
	b.Run("PrivateKeyToDER", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := keyPair.PrivateKeyToDER()
			if err != nil {
				b.Fatalf("DER conversion failed: %v", err)
			}
		}
	})

	derData, _ := keyPair.PrivateKeyToDER()
	b.Run("ECDSAKeyPairFromDER", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := ECDSAKeyPairFromDER(derData)
			if err != nil {
				b.Fatalf("DER reconstruction failed: %v", err)
			}
		}
	})

	// SSH operations
	b.Run("PrivateKeyToSSH", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := keyPair.PrivateKeyToSSH("bench", "")
			if err != nil {
				b.Fatalf("SSH conversion failed: %v", err)
			}
		}
	})

	sshData, _ := keyPair.PrivateKeyToSSH("bench", "")
	b.Run("ECDSAKeyPairFromSSH", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := ECDSAKeyPairFromSSH(sshData, "")
			if err != nil {
				b.Fatalf("SSH reconstruction failed: %v", err)
			}
		}
	})

	b.Run("PublicKeyToSSH", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := keyPair.PublicKeyToSSH("bench@example.com")
			if err != nil {
				b.Fatalf("SSH public conversion failed: %v", err)
			}
		}
	})
}
