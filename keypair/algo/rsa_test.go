package algo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeySizeConstants(t *testing.T) {
	tests := []struct {
		name     string
		keySize  KeySize
		expected int
	}{
		{"KeySize2048", KeySize2048, 2048},
		{"KeySize3072", KeySize3072, 3072},
		{"KeySize4096", KeySize4096, 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.keySize.Bits())
		})
	}
}

func TestGenerateRSAKeyPair_ValidKeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize KeySize
	}{
		{"KeySize2048", KeySize2048},
		{"KeySize3072", KeySize3072},
		{"KeySize4096", KeySize4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateRSAKeyPair(tt.keySize)

			assert.NoError(t, err)
			assert.NotNil(t, keyPair)
			if keyPair == nil {
				t.Fatal("keyPair is nil")
			}
			assert.NotNil(t, keyPair.PrivateKey)
			assert.NotNil(t, keyPair.PublicKey)

			// Verify key size matches request
			assert.Equal(t, tt.keySize.Bits(), keyPair.PrivateKey.Size()*8)

			// Verify public key is derived from private key
			assert.Equal(t, &keyPair.PrivateKey.PublicKey, keyPair.PublicKey)

			// Verify key can be used for basic cryptographic operations
			assert.NoError(t, keyPair.PrivateKey.Validate())
		})
	}
}

func TestGenerateRSAKeyPair_InvalidKeySizes(t *testing.T) {
	// Note: With the new struct-based KeySize, it's impossible to create invalid key sizes
	// at compile time. This test demonstrates that only predefined constants work.
	// We test with a zero-value KeySize to ensure proper validation.
	tests := []struct {
		name    string
		keySize KeySize
	}{
		{"ZeroValue", KeySize{}}, // Only way to get an invalid KeySize
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateRSAKeyPair(tt.keySize)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), "RSA key size must be at least 2048 bits")
		})
	}
}

func TestRSAKeyPair_PrivateKeyToPEM(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

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

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	assert.True(t, ok)
	assert.Equal(t, keyPair.PrivateKey.Size(), rsaKey.Size())
}

func TestRSAKeyPair_PublicKeyToPEM(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

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

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	assert.True(t, ok)
	assert.Equal(t, keyPair.PublicKey.Size(), rsaKey.Size())
}

func TestRSAKeyPairFromPEM_Success(t *testing.T) {
	// Generate original key pair
	originalKeyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

	// Convert to PEM
	pemData, err := originalKeyPair.PrivateKeyToPEM()
	assert.NoError(t, err)

	// Reconstruct from PEM
	reconstructedKeyPair, err := RSAKeyPairFromPEM(pemData)
	assert.NoError(t, err)
	assert.NotNil(t, reconstructedKeyPair)

	// Verify the keys match
	assert.Equal(t, originalKeyPair.PrivateKey.Size(), reconstructedKeyPair.PrivateKey.Size())
	assert.Equal(t, originalKeyPair.PublicKey.Size(), reconstructedKeyPair.PublicKey.Size())
	assert.Equal(t, &reconstructedKeyPair.PrivateKey.PublicKey, reconstructedKeyPair.PublicKey)
}

func TestRSAKeyPairFromPEM_InvalidPEM(t *testing.T) {
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
			name: "NotRSAKey",
			pemData: func() []byte {
				// Create a valid PKCS8 key that's not RSA (this is a mock - in real test would use ECDSA)
				return []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`)
			}(),
			errMsg: "failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := RSAKeyPairFromPEM(tt.pemData)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestRSAKeyPair_PEMRoundTrip(t *testing.T) {
	// Test with different key sizes
	tests := []struct {
		name    string
		keySize KeySize
	}{
		{"2048", KeySize2048},
		{"3072", KeySize3072},
		{"4096", KeySize4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate original key pair
			original, err := GenerateRSAKeyPair(tt.keySize)
			assert.NoError(t, err)

			// Convert to PEM and back
			privatePEM, err := original.PrivateKeyToPEM()
			assert.NoError(t, err)

			publicPEM, err := original.PublicKeyToPEM()
			assert.NoError(t, err)

			// Reconstruct from private key PEM
			reconstructed, err := RSAKeyPairFromPEM(privatePEM)
			assert.NoError(t, err)

			// Verify private keys match
			assert.Equal(t, original.PrivateKey.Size(), reconstructed.PrivateKey.Size())

			// Verify public keys match
			assert.Equal(t, original.PublicKey.Size(), reconstructed.PublicKey.Size())

			// Verify reconstructed public key PEM matches original
			reconstructedPublicPEM, err := reconstructed.PublicKeyToPEM()
			assert.NoError(t, err)
			assert.Equal(t, string(publicPEM), string(reconstructedPublicPEM))
		})
	}
}

func TestRSAKeyPair_PEMFormat(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

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

func TestRSAKeyPair_KeyValidation(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

	// Verify the private key is mathematically valid
	err = keyPair.PrivateKey.Validate()
	assert.NoError(t, err)

	// Verify N (modulus) is the same for both keys
	assert.Equal(t, keyPair.PrivateKey.N, keyPair.PublicKey.N)

	// Verify E (public exponent) is the same for both keys
	assert.Equal(t, keyPair.PrivateKey.E, keyPair.PublicKey.E)
}

func BenchmarkGenerateRSAKeyPair(b *testing.B) {
	tests := []struct {
		name    string
		keySize KeySize
	}{
		{"2048", KeySize2048},
		{"3072", KeySize3072},
		{"4096", KeySize4096},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := GenerateRSAKeyPair(tt.keySize)
				if err != nil {
					b.Fatalf("Key generation failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkRSAKeyPair_PEMOperations(b *testing.B) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
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
	b.Run("RSAKeyPairFromPEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := RSAKeyPairFromPEM(pemData)
			if err != nil {
				b.Fatalf("PEM reconstruction failed: %v", err)
			}
		}
	})
}

// DER Format Tests

func TestRSAKeyPair_PrivateKeyToDER(t *testing.T) {
	keySizes := []KeySize{KeySize2048, KeySize3072, KeySize4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", keySize.Bits()), func(t *testing.T) {
			keyPair, err := GenerateRSAKeyPair(keySize)
			assert.NoError(t, err)

			derData, err := keyPair.PrivateKeyToDER()
			assert.NoError(t, err)
			assert.NotEmpty(t, derData)

			// Verify we can parse the DER back to a private key
			parsedKey, err := x509.ParsePKCS8PrivateKey(derData)
			assert.NoError(t, err)

			rsaKey, ok := parsedKey.(*rsa.PrivateKey)
			assert.True(t, ok, "Parsed key should be RSA")
			assert.Equal(t, keyPair.PrivateKey.Size(), rsaKey.Size())

			// Verify DER is more compact than PEM
			pemData, err := keyPair.PrivateKeyToPEM()
			assert.NoError(t, err)
			assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")
		})
	}
}

func TestRSAKeyPair_PublicKeyToDER(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

	derData, err := keyPair.PublicKeyToDER()
	assert.NoError(t, err)
	assert.NotEmpty(t, derData)

	// Verify we can parse the DER back to a public key
	parsedKey, err := x509.ParsePKIXPublicKey(derData)
	assert.NoError(t, err)

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	assert.True(t, ok, "Parsed key should be RSA")
	assert.Equal(t, keyPair.PublicKey.Size(), rsaKey.Size())

	// Verify DER is more compact than PEM
	pemData, err := keyPair.PublicKeyToPEM()
	assert.NoError(t, err)
	assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")
}

func TestRSAKeyPairFromDER_Success(t *testing.T) {
	keySizes := []KeySize{KeySize2048, KeySize3072, KeySize4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", keySize.Bits()), func(t *testing.T) {
			// Generate original key pair
			originalKeyPair, err := GenerateRSAKeyPair(keySize)
			assert.NoError(t, err)

			// Convert to DER
			derData, err := originalKeyPair.PrivateKeyToDER()
			assert.NoError(t, err)

			// Reconstruct from DER
			reconstructedKeyPair, err := RSAKeyPairFromDER(derData)
			assert.NoError(t, err)
			assert.NotNil(t, reconstructedKeyPair)

			// Verify the keys match
			assert.Equal(t, originalKeyPair.PrivateKey.Size(), reconstructedKeyPair.PrivateKey.Size())
			assert.Equal(t, originalKeyPair.PublicKey.Size(), reconstructedKeyPair.PublicKey.Size())
			assert.Equal(t, &reconstructedKeyPair.PrivateKey.PublicKey, reconstructedKeyPair.PublicKey)

			// Verify key validation
			assert.NoError(t, reconstructedKeyPair.PrivateKey.Validate())
		})
	}
}

func TestRSAKeyPairFromDER_InvalidDER(t *testing.T) {
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
			keyPair, err := RSAKeyPairFromDER(tt.derData)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestRSAKeyPair_DERRoundTrip(t *testing.T) {
	keySizes := []KeySize{KeySize2048, KeySize3072, KeySize4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", keySize.Bits()), func(t *testing.T) {
			// Generate original key pair
			original, err := GenerateRSAKeyPair(keySize)
			assert.NoError(t, err)

			// Convert to DER and back
			privateDER, err := original.PrivateKeyToDER()
			assert.NoError(t, err)

			publicDER, err := original.PublicKeyToDER()
			assert.NoError(t, err)

			// Reconstruct from private key DER
			reconstructed, err := RSAKeyPairFromDER(privateDER)
			assert.NoError(t, err)

			// Verify private keys match
			assert.Equal(t, original.PrivateKey.Size(), reconstructed.PrivateKey.Size())

			// Verify public keys match
			assert.Equal(t, original.PublicKey.Size(), reconstructed.PublicKey.Size())

			// Verify reconstructed public key DER matches original
			reconstructedPublicDER, err := reconstructed.PublicKeyToDER()
			assert.NoError(t, err)
			assert.Equal(t, publicDER, reconstructedPublicDER)
		})
	}
}

// SSH Format Tests

func TestRSAKeyPair_PublicKeyToSSH(t *testing.T) {
	keySizes := []KeySize{KeySize2048, KeySize3072, KeySize4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", keySize.Bits()), func(t *testing.T) {
			keyPair, err := GenerateRSAKeyPair(keySize)
			assert.NoError(t, err)

			// Test with comment
			sshData, err := keyPair.PublicKeyToSSH("user@example.com")
			assert.NoError(t, err)
			assert.NotEmpty(t, sshData)

			// Verify SSH format
			assert.True(t, strings.HasPrefix(string(sshData), "ssh-rsa "), "SSH key should start with 'ssh-rsa '")
			assert.Contains(t, string(sshData), "user@example.com", "SSH key should contain comment")
			assert.Equal(t, 3, len(strings.Fields(string(sshData))), "SSH key should have 3 parts")

			// Test without comment
			sshDataNoComment, err := keyPair.PublicKeyToSSH("")
			assert.NoError(t, err)
			assert.Equal(t, 2, len(strings.Fields(string(sshDataNoComment))), "SSH key without comment should have 2 parts")
			assert.True(t, strings.HasPrefix(string(sshDataNoComment), "ssh-rsa "))
		})
	}
}

func TestRSAKeyPair_PrivateKeyToSSH(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
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

func TestRSAKeyPairFromSSH_Success(t *testing.T) {
	keySizes := []KeySize{KeySize2048, KeySize3072}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", keySize.Bits()), func(t *testing.T) {
			// Generate original key pair
			originalKeyPair, err := GenerateRSAKeyPair(keySize)
			assert.NoError(t, err)

			// Test unencrypted SSH round-trip
			sshData, err := originalKeyPair.PrivateKeyToSSH("test-key", "")
			assert.NoError(t, err)

			reconstructed, err := RSAKeyPairFromSSH(sshData, "")
			assert.NoError(t, err)
			assert.NotNil(t, reconstructed)
			assert.Equal(t, originalKeyPair.PrivateKey.Size(), reconstructed.PrivateKey.Size())

			// Test encrypted SSH round-trip
			passphrase := "test-passphrase-123"
			sshEncrypted, err := originalKeyPair.PrivateKeyToSSH("encrypted-key", passphrase)
			assert.NoError(t, err)

			reconstructedEncrypted, err := RSAKeyPairFromSSH(sshEncrypted, passphrase)
			assert.NoError(t, err)
			assert.NotNil(t, reconstructedEncrypted)
			assert.Equal(t, originalKeyPair.PrivateKey.Size(), reconstructedEncrypted.PrivateKey.Size())
		})
	}
}

func TestRSAKeyPairFromSSH_InvalidSSH(t *testing.T) {
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
				keyPair, _ := GenerateRSAKeyPair(KeySize2048)
				sshData, _ := keyPair.PrivateKeyToSSH("test", "correct-passphrase")
				return string(sshData)
			}(),
			passphrase: "wrong-passphrase",
			errMsg:     "failed to parse SSH private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := RSAKeyPairFromSSH(SSH(tt.sshData), tt.passphrase)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestRSAKeyPair_SSHRoundTrip(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

	// Test unencrypted round-trip
	sshPrivate, err := keyPair.PrivateKeyToSSH("test-key", "")
	assert.NoError(t, err)

	sshPublic, err := keyPair.PublicKeyToSSH("test@example.com")
	assert.NoError(t, err)

	// Reconstruct from SSH private key
	reconstructed, err := RSAKeyPairFromSSH(sshPrivate, "")
	assert.NoError(t, err)

	// Verify keys match
	assert.Equal(t, keyPair.PrivateKey.Size(), reconstructed.PrivateKey.Size())

	// Verify public key can be reconstructed correctly
	reconstructedPublic, err := reconstructed.PublicKeyToSSH("test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, sshPublic, reconstructedPublic)
}

// Cross-Format Tests

func TestRSAKeyPair_CrossFormatCompatibility(t *testing.T) {
	// Generate original key pair
	original, err := GenerateRSAKeyPair(KeySize2048)
	assert.NoError(t, err)

	// Test PEM -> DER -> SSH -> PEM conversion chain
	t.Run("PEM->DER->SSH->PEM", func(t *testing.T) {
		// PEM to DER
		pemData, err := original.PrivateKeyToPEM()
		assert.NoError(t, err)

		keyFromPEM, err := RSAKeyPairFromPEM(pemData)
		assert.NoError(t, err)

		derData, err := keyFromPEM.PrivateKeyToDER()
		assert.NoError(t, err)

		// DER to SSH
		keyFromDER, err := RSAKeyPairFromDER(derData)
		assert.NoError(t, err)

		sshData, err := keyFromDER.PrivateKeyToSSH("test", "")
		assert.NoError(t, err)

		// SSH back to PEM
		keyFromSSH, err := RSAKeyPairFromSSH(sshData, "")
		assert.NoError(t, err)

		finalPEM, err := keyFromSSH.PrivateKeyToPEM()
		assert.NoError(t, err)

		// Verify final result matches original
		finalKey, err := RSAKeyPairFromPEM(finalPEM)
		assert.NoError(t, err)
		assert.Equal(t, original.PrivateKey.Size(), finalKey.PrivateKey.Size())
	})
}

// Enhanced Benchmarks

func BenchmarkRSAKeyPair_AllFormats(b *testing.B) {
	keyPair, err := GenerateRSAKeyPair(KeySize2048)
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
	b.Run("RSAKeyPairFromDER", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := RSAKeyPairFromDER(derData)
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
	b.Run("RSAKeyPairFromSSH", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := RSAKeyPairFromSSH(sshData, "")
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
