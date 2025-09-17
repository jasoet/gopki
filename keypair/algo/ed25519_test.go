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

// DER Format Tests

func TestEd25519KeyPair_PrivateKeyToDER(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	derData, err := keyPair.PrivateKeyToDER()
	assert.NoError(t, err)
	assert.NotEmpty(t, derData)

	// Verify we can parse the DER back to a private key
	parsedKey, err := x509.ParsePKCS8PrivateKey(derData)
	assert.NoError(t, err)

	ed25519Key, ok := parsedKey.(ed25519.PrivateKey)
	assert.True(t, ok, "Parsed key should be Ed25519")
	assert.Equal(t, keyPair.PrivateKey, ed25519Key)

	// Verify DER is more compact than PEM
	pemData, err := keyPair.PrivateKeyToPEM()
	assert.NoError(t, err)
	assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")

	// Verify Ed25519 DER is very compact (should be around 48 bytes)
	assert.True(t, len(derData) < 60, "Ed25519 DER should be very compact")
}

func TestEd25519KeyPair_PublicKeyToDER(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	derData, err := keyPair.PublicKeyToDER()
	assert.NoError(t, err)
	assert.NotEmpty(t, derData)

	// Verify we can parse the DER back to a public key
	parsedKey, err := x509.ParsePKIXPublicKey(derData)
	assert.NoError(t, err)

	ed25519Key, ok := parsedKey.(ed25519.PublicKey)
	assert.True(t, ok, "Parsed key should be Ed25519")
	assert.Equal(t, keyPair.PublicKey, ed25519Key)

	// Verify DER is more compact than PEM
	pemData, err := keyPair.PublicKeyToPEM()
	assert.NoError(t, err)
	assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")

	// Verify Ed25519 public key DER is very compact (should be around 44 bytes)
	assert.True(t, len(derData) < 50, "Ed25519 public key DER should be very compact")
}

func TestEd25519KeyPairFromDER_Success(t *testing.T) {
	// Generate original key pair
	originalKeyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Convert to DER
	derData, err := originalKeyPair.PrivateKeyToDER()
	assert.NoError(t, err)

	// Reconstruct from DER
	reconstructedKeyPair, err := Ed25519KeyPairFromDER(derData)
	assert.NoError(t, err)
	assert.NotNil(t, reconstructedKeyPair)

	// Verify the keys match exactly
	assert.Equal(t, originalKeyPair.PrivateKey, reconstructedKeyPair.PrivateKey)
	assert.Equal(t, originalKeyPair.PublicKey, reconstructedKeyPair.PublicKey)

	// Verify public key is derived from private key
	expectedPublicKey := reconstructedKeyPair.PrivateKey.Public().(ed25519.PublicKey)
	assert.Equal(t, expectedPublicKey, reconstructedKeyPair.PublicKey)

	// Verify key sizes are correct
	assert.Equal(t, ed25519.PrivateKeySize, len(reconstructedKeyPair.PrivateKey))
	assert.Equal(t, ed25519.PublicKeySize, len(reconstructedKeyPair.PublicKey))
}

func TestEd25519KeyPairFromDER_InvalidDER(t *testing.T) {
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
			keyPair, err := Ed25519KeyPairFromDER(tt.derData)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestEd25519KeyPair_DERRoundTrip(t *testing.T) {
	// Generate original key pair
	original, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Convert to DER and back
	privateDER, err := original.PrivateKeyToDER()
	assert.NoError(t, err)

	publicDER, err := original.PublicKeyToDER()
	assert.NoError(t, err)

	// Reconstruct from private key DER
	reconstructed, err := Ed25519KeyPairFromDER(privateDER)
	assert.NoError(t, err)

	// Verify private keys match exactly
	assert.Equal(t, original.PrivateKey, reconstructed.PrivateKey)

	// Verify public keys match exactly
	assert.Equal(t, original.PublicKey, reconstructed.PublicKey)

	// Verify reconstructed public key DER matches original
	reconstructedPublicDER, err := reconstructed.PublicKeyToDER()
	assert.NoError(t, err)
	assert.Equal(t, publicDER, reconstructedPublicDER)
}

// SSH Format Tests

func TestEd25519KeyPair_PublicKeyToSSH(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Test with comment
	sshData, err := keyPair.PublicKeyToSSH("user@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, sshData)

	// Verify SSH format starts with Ed25519 prefix
	assert.True(t, strings.HasPrefix(sshData, "ssh-ed25519 "), "SSH key should start with 'ssh-ed25519 '")
	assert.Contains(t, sshData, "user@example.com", "SSH key should contain comment")
	assert.Equal(t, 3, len(strings.Fields(sshData)), "SSH key should have 3 parts")

	// Test without comment
	sshDataNoComment, err := keyPair.PublicKeyToSSH("")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(strings.Fields(sshDataNoComment)), "SSH key without comment should have 2 parts")
	assert.True(t, strings.HasPrefix(sshDataNoComment, "ssh-ed25519 "))

	// Verify the SSH public key is properly formatted and compact
	parts := strings.Fields(sshData)
	assert.Equal(t, "ssh-ed25519", parts[0])
	assert.True(t, len(parts[1]) > 40, "Base64 encoded key should be substantial")
}

func TestEd25519KeyPair_PrivateKeyToSSH(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
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

	// Ed25519 SSH keys should be relatively compact
	assert.True(t, len(sshData) < 500, "Unencrypted Ed25519 SSH key should be compact")
}

func TestEd25519KeyPairFromSSH_Success(t *testing.T) {
	// Generate original key pair
	originalKeyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Test unencrypted SSH round-trip
	sshData, err := originalKeyPair.PrivateKeyToSSH("test-key", "")
	assert.NoError(t, err)

	reconstructed, err := Ed25519KeyPairFromSSH(sshData, "")
	assert.NoError(t, err)
	assert.NotNil(t, reconstructed)
	assert.Equal(t, originalKeyPair.PrivateKey, reconstructed.PrivateKey)
	assert.Equal(t, originalKeyPair.PublicKey, reconstructed.PublicKey)

	// Test encrypted SSH round-trip
	passphrase := "test-passphrase-123"
	sshEncrypted, err := originalKeyPair.PrivateKeyToSSH("encrypted-key", passphrase)
	assert.NoError(t, err)

	reconstructedEncrypted, err := Ed25519KeyPairFromSSH(sshEncrypted, passphrase)
	assert.NoError(t, err)
	assert.NotNil(t, reconstructedEncrypted)
	assert.Equal(t, originalKeyPair.PrivateKey, reconstructedEncrypted.PrivateKey)
	assert.Equal(t, originalKeyPair.PublicKey, reconstructedEncrypted.PublicKey)

	// Verify cryptographic properties of reconstructed keys
	message := []byte("test message for Ed25519 signature verification")
	signature := ed25519.Sign(reconstructed.PrivateKey, message)
	valid := ed25519.Verify(reconstructed.PublicKey, message, signature)
	assert.True(t, valid, "Reconstructed key should be cryptographically valid")
}

func TestEd25519KeyPairFromSSH_InvalidSSH(t *testing.T) {
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
				keyPair, _ := GenerateEd25519KeyPair()
				sshData, _ := keyPair.PrivateKeyToSSH("test", "correct-passphrase")
				return sshData
			}(),
			passphrase: "wrong-passphrase",
			errMsg:     "failed to parse SSH private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := Ed25519KeyPairFromSSH(tt.sshData, tt.passphrase)

			assert.Error(t, err)
			assert.Nil(t, keyPair)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestEd25519KeyPair_SSHRoundTrip(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Test unencrypted round-trip
	sshPrivate, err := keyPair.PrivateKeyToSSH("test-key", "")
	assert.NoError(t, err)

	sshPublic, err := keyPair.PublicKeyToSSH("test@example.com")
	assert.NoError(t, err)

	// Reconstruct from SSH private key
	reconstructed, err := Ed25519KeyPairFromSSH(sshPrivate, "")
	assert.NoError(t, err)

	// Verify keys match exactly
	assert.Equal(t, keyPair.PrivateKey, reconstructed.PrivateKey)
	assert.Equal(t, keyPair.PublicKey, reconstructed.PublicKey)

	// Verify public key can be reconstructed correctly
	reconstructedPublic, err := reconstructed.PublicKeyToSSH("test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, sshPublic, reconstructedPublic)

	// Test encrypted round-trip
	passphrase := "secure-passphrase-456"
	sshEncrypted, err := keyPair.PrivateKeyToSSH("encrypted-test", passphrase)
	assert.NoError(t, err)

	reconstructedEncrypted, err := Ed25519KeyPairFromSSH(sshEncrypted, passphrase)
	assert.NoError(t, err)
	assert.Equal(t, keyPair.PrivateKey, reconstructedEncrypted.PrivateKey)
	assert.Equal(t, keyPair.PublicKey, reconstructedEncrypted.PublicKey)
}

// Cross-Format Tests

func TestEd25519KeyPair_CrossFormatCompatibility(t *testing.T) {
	// Generate original key pair
	original, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Test PEM -> DER -> SSH -> PEM conversion chain
	t.Run("PEM->DER->SSH->PEM", func(t *testing.T) {
		// PEM to DER
		pemData, err := original.PrivateKeyToPEM()
		assert.NoError(t, err)

		keyFromPEM, err := Ed25519KeyPairFromPEM(pemData)
		assert.NoError(t, err)

		derData, err := keyFromPEM.PrivateKeyToDER()
		assert.NoError(t, err)

		// DER to SSH
		keyFromDER, err := Ed25519KeyPairFromDER(derData)
		assert.NoError(t, err)

		sshData, err := keyFromDER.PrivateKeyToSSH("test", "")
		assert.NoError(t, err)

		// SSH back to PEM
		keyFromSSH, err := Ed25519KeyPairFromSSH(sshData, "")
		assert.NoError(t, err)

		finalPEM, err := keyFromSSH.PrivateKeyToPEM()
		assert.NoError(t, err)

		// Verify final result matches original
		finalKey, err := Ed25519KeyPairFromPEM(finalPEM)
		assert.NoError(t, err)
		assert.Equal(t, original.PrivateKey, finalKey.PrivateKey)
		assert.Equal(t, original.PublicKey, finalKey.PublicKey)
	})

	// Test DER -> SSH -> DER conversion chain
	t.Run("DER->SSH->DER", func(t *testing.T) {
		// Start with DER
		originalDER, err := original.PrivateKeyToDER()
		assert.NoError(t, err)

		keyFromDER, err := Ed25519KeyPairFromDER(originalDER)
		assert.NoError(t, err)

		// DER to SSH
		sshData, err := keyFromDER.PrivateKeyToSSH("cross-format", "")
		assert.NoError(t, err)

		// SSH back to DER
		keyFromSSH, err := Ed25519KeyPairFromSSH(sshData, "")
		assert.NoError(t, err)

		finalDER, err := keyFromSSH.PrivateKeyToDER()
		assert.NoError(t, err)

		// Verify DER data matches
		assert.Equal(t, originalDER, finalDER)
	})
}

func TestEd25519KeyPair_FormatCompactness(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)

	// Get all formats
	pemData, err := keyPair.PrivateKeyToPEM()
	assert.NoError(t, err)

	derData, err := keyPair.PrivateKeyToDER()
	assert.NoError(t, err)

	sshData, err := keyPair.PrivateKeyToSSH("test", "")
	assert.NoError(t, err)

	// Verify size ordering: DER < SSH < PEM (generally)
	assert.True(t, len(derData) < len(pemData), "DER should be more compact than PEM")

	// Ed25519 is very efficient, so all formats should be relatively compact
	assert.True(t, len(derData) < 60, "Ed25519 DER should be very compact")
	assert.True(t, len(pemData) < 150, "Ed25519 PEM should be compact")
	assert.True(t, len(sshData) < 500, "Ed25519 SSH should be reasonably compact")

	t.Logf("Format sizes - DER: %d bytes, PEM: %d bytes, SSH: %d bytes",
		len(derData), len(pemData), len(sshData))
}

// Enhanced Benchmarks

func BenchmarkEd25519KeyPair_AllFormats(b *testing.B) {
	keyPair, err := GenerateEd25519KeyPair()
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
	b.Run("Ed25519KeyPairFromDER", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := Ed25519KeyPairFromDER(derData)
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
	b.Run("Ed25519KeyPairFromSSH", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := Ed25519KeyPairFromSSH(sshData, "")
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

func BenchmarkEd25519_CrossFormatConversion(b *testing.B) {
	keyPair, err := GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	b.Run("PEM->DER->SSH->PEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// PEM to DER
			pemData, _ := keyPair.PrivateKeyToPEM()
			keyFromPEM, _ := Ed25519KeyPairFromPEM(pemData)
			derData, _ := keyFromPEM.PrivateKeyToDER()

			// DER to SSH
			keyFromDER, _ := Ed25519KeyPairFromDER(derData)
			sshData, _ := keyFromDER.PrivateKeyToSSH("bench", "")

			// SSH back to PEM
			keyFromSSH, _ := Ed25519KeyPairFromSSH(sshData, "")
			_, _ = keyFromSSH.PrivateKeyToPEM()
		}
	})
}
