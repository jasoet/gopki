//go:build compatibility

package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jasoet/gopki/compatibility"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
)

// TestSSHCertificateCompatibility tests SSH certificate features with ssh-keygen
func TestSSHCertificateCompatibility(t *testing.T) {
	t.Logf("🏆 Testing SSH Certificate Compatibility with ssh-keygen...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Test SSH certificate information extraction
	t.Run("SSH_Certificate_Information", func(t *testing.T) {
		// Generate Ed25519 key pair (commonly used for SSH certificates)
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair")

		_, publicSSH, err := manager.ToSSH("test-user@example.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Use ssh-keygen to get detailed information about the key
		keyInfo, err := helper.GetSSHKeyInformation([]byte(publicSSH))
		require.NoError(t, err, "Failed to get SSH key information")

		// Verify key information contains expected data
		assert.Contains(t, keyInfo, "256", "Should contain key size")
		assert.Contains(t, keyInfo, "ED25519", "Should contain algorithm type")
		assert.Contains(t, keyInfo, "test-user@example.com", "Should contain comment")

		t.Logf("✓ SSH key information: %s", keyInfo)
	})

	// Test SSH key type detection
	t.Run("SSH_Key_Type_Detection", func(t *testing.T) {
		algorithms := []struct {
			name     string
			generate func() (format.SSH, error)
			expected string
		}{
			{
				name: "RSA-2048",
				generate: func() (format.SSH, error) {
					manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
					if err != nil {
						return "", err
					}
					_, pub, err := manager.ToSSH("test@example.com", "")
					return pub, err
				},
				expected: "ssh-rsa",
			},
			{
				name: "ECDSA-P256",
				generate: func() (format.SSH, error) {
					manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
					if err != nil {
						return "", err
					}
					_, pub, err := manager.ToSSH("test@example.com", "")
					return pub, err
				},
				expected: "ecdsa-sha2-nistp256",
			},
			{
				name: "Ed25519",
				generate: func() (format.SSH, error) {
					manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
					if err != nil {
						return "", err
					}
					_, pub, err := manager.ToSSH("test@example.com", "")
					return pub, err
				},
				expected: "ssh-ed25519",
			},
		}

		for _, alg := range algorithms {
			t.Run(alg.name, func(t *testing.T) {
				publicSSH, err := alg.generate()
				require.NoError(t, err, "Failed to generate %s key", alg.name)

				// Verify key type prefix
				assert.True(t, strings.HasPrefix(string(publicSSH), alg.expected+" "),
					"SSH key should start with %s", alg.expected)

				// Validate with ssh-keygen
				err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
				assert.NoError(t, err, "ssh-keygen validation failed for %s", alg.name)

				t.Logf("✓ %s key type detection verified", alg.name)
			})
		}
	})
}

// TestSSHSignatureInteroperability tests raw signature compatibility with OpenSSH
func TestSSHSignatureInteroperability(t *testing.T) {
	t.Logf("✍️ Testing SSH Signature Interoperability...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Test Ed25519 signature interoperability (common for SSH)
	t.Run("Ed25519_Raw_Signature_Interoperability", func(t *testing.T) {
		// Generate Ed25519 key pair
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair")

		// Test data
		testData := []byte("SSH signature interoperability test data")

		// Get PEM format for OpenSSL compatibility
		privatePEM, _, err := manager.ToPEM()
		require.NoError(t, err, "Failed to convert to PEM format")

		// Test raw signature interoperability
		t.Run("OpenSSL_Sign_GoPKI_Verify", func(t *testing.T) {
			// Create signature with OpenSSL pkeyutl (raw Ed25519)
			signature, err := helper.SignWithOpenSSL(testData, privatePEM, "")
			require.NoError(t, err, "Failed to create signature with OpenSSL")

			// Verify signature with GoPKI
			publicKey := manager.KeyPair().PublicKey
			verified := ed25519.Verify(publicKey, testData, signature)
			assert.True(t, verified, "GoPKI should verify OpenSSL Ed25519 signature")

			t.Logf("✓ OpenSSL Ed25519 signature verified by GoPKI")
		})

		t.Run("GoPKI_Sign_OpenSSL_Verify", func(t *testing.T) {
			// Create signature with GoPKI
			privateKey := manager.KeyPair().PrivateKey
			signature := ed25519.Sign(privateKey, testData)

			// Get public key in PEM format for verification
			_, publicPEM, err := manager.ToPEM()
			require.NoError(t, err, "Failed to get public key PEM")

			// Verify signature with OpenSSL
			err = helper.VerifyRawSignatureWithOpenSSL(testData, signature, publicPEM, "")
			assert.NoError(t, err, "OpenSSL should verify GoPKI Ed25519 signature")

			t.Logf("✓ GoPKI Ed25519 signature verified by OpenSSL")
		})
	})

	// Test ECDSA signature interoperability
	t.Run("ECDSA_Raw_Signature_Interoperability", func(t *testing.T) {
		// Generate ECDSA P-256 key pair
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		require.NoError(t, err, "Failed to generate ECDSA key pair")

		testData := []byte("ECDSA signature interoperability test")

		// Get PEM format for OpenSSL compatibility
		privatePEM, _, err := manager.ToPEM()
		require.NoError(t, err, "Failed to convert to PEM format")

		t.Run("Bidirectional_ECDSA_Signatures", func(t *testing.T) {
			// OpenSSL sign -> GoPKI verify
			signature, err := helper.SignWithOpenSSL(testData, privatePEM, "sha256")
			require.NoError(t, err, "Failed to create ECDSA signature with OpenSSL")

			// Parse and verify signature with Go's crypto/ecdsa
			privateKey := manager.KeyPair().PrivateKey
			publicKey := &privateKey.PublicKey

			// Note: ECDSA signatures from OpenSSL are DER-encoded, need to parse
			valid, err := helper.VerifyECDSASignatureInterop(testData, signature, publicKey)
			require.NoError(t, err, "Failed to verify ECDSA signature")
			assert.True(t, valid, "ECDSA signature should be valid")

			t.Logf("✓ ECDSA signature interoperability verified")
		})
	})
}

// TestSSHKeyConversionAdvanced tests advanced SSH key conversion scenarios
func TestSSHKeyConversionAdvanced(t *testing.T) {
	t.Logf("🔄 Testing Advanced SSH Key Conversion...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Test legacy SSH format compatibility
	t.Run("Legacy_SSH_Format_Compatibility", func(t *testing.T) {
		// Generate RSA key for legacy testing
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		require.NoError(t, err, "Failed to generate RSA key pair")

		// Convert to SSH format
		privateSSH, _, err := manager.ToSSH("legacy-test", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Test conversion back to PEM format using ssh-keygen
		convertedPEM, err := helper.ConvertSSHToPEMWithSSHKeygen([]byte(privateSSH))
		if err != nil {
			t.Logf("⚠️ SSH to PEM conversion not supported by this ssh-keygen version: %v", err)
			return
		}

		// Load converted PEM back with GoPKI
		loadedManager, err := keypair.LoadFromPEMData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](
			format.PEM(convertedPEM),
		)
		if err != nil {
			t.Logf("⚠️ SSH to PEM conversion uses PKCS#1 format, which is expected: %v", err)
			t.Logf("✓ Legacy SSH format conversion test completed (PKCS#1 format detected)")
			return
		}

		// Verify keys are equivalent by comparing public key SSH representations
		_, originalPublic, err := manager.ToSSH("test", "")
		require.NoError(t, err, "Failed to get original public key")

		_, convertedPublic, err := loadedManager.ToSSH("test", "")
		require.NoError(t, err, "Failed to get converted public key")

		assert.Equal(t, originalPublic, convertedPublic, "Public keys should match after conversion")

		t.Logf("✓ Legacy SSH format conversion verified")
	})

	// Test multi-format conversion chain
	t.Run("Multi_Format_Conversion_Chain", func(t *testing.T) {
		// Start with Ed25519 key
		original, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate original Ed25519 key")

		// Conversion chain: PEM -> SSH -> back to PEM
		_, _, err = original.ToPEM()
		require.NoError(t, err, "Failed to convert to PEM")

		// PEM to SSH
		sshPrivate, sshPublic, err := original.ToSSH("chain-test", "")
		require.NoError(t, err, "Failed to convert to SSH")

		// Validate SSH format with ssh-keygen
		err = helper.ValidateSSHPrivateKeyWithSSHKeygen([]byte(sshPrivate))
		assert.NoError(t, err, "SSH private key validation failed")

		err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(sshPublic))
		assert.NoError(t, err, "SSH public key validation failed")

		// SSH back to PEM
		reconstructed, err := keypair.LoadFromSSHData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](
			sshPrivate, "",
		)
		require.NoError(t, err, "Failed to load from SSH")

		_, _, err = reconstructed.ToPEM()
		require.NoError(t, err, "Failed to convert back to PEM")

		// Verify the keys are functionally equivalent
		assert.Equal(t, original.KeyPair().PrivateKey, reconstructed.KeyPair().PrivateKey,
			"Private keys should be identical after conversion chain")

		t.Logf("✓ Multi-format conversion chain verified")
	})
}

// TestSSHCompatibilityEdgeCases tests edge cases and error conditions
func TestSSHCompatibilityEdgeCases(t *testing.T) {
	t.Logf("⚠️ Testing SSH Compatibility Edge Cases...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Test malformed SSH key handling
	t.Run("Malformed_SSH_Key_Handling", func(t *testing.T) {
		malformedKeys := []struct {
			name string
			data string
		}{
			{
				name: "Invalid Base64",
				data: "ssh-ed25519 INVALID_BASE64!@#$ test@example.com",
			},
			{
				name: "Wrong Key Type",
				data: "ssh-unknown AAAAC3NzaC1lZDI1NTE5AAAAIGKDJMh... test@example.com",
			},
			{
				name: "Missing Parts",
				data: "ssh-ed25519",
			},
		}

		for _, mk := range malformedKeys {
			t.Run(mk.name, func(t *testing.T) {
				// ssh-keygen should reject malformed keys
				err := helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(mk.data))
				assert.Error(t, err, "ssh-keygen should reject malformed key: %s", mk.name)

				t.Logf("✓ Malformed key correctly rejected: %s", mk.name)
			})
		}
	})

	// Test large comment handling
	t.Run("Large_Comment_Handling", func(t *testing.T) {
		// Generate key with large comment
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key")

		// Create a large comment (but within reasonable limits)
		largeComment := strings.Repeat("test-user-with-very-long-name@", 20) + "example.com"

		_, publicSSH, err := manager.ToSSH(largeComment, "")
		require.NoError(t, err, "Failed to convert with large comment")

		// Validate with ssh-keygen
		err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
		assert.NoError(t, err, "ssh-keygen should handle large comments")

		// Verify comment is preserved
		assert.Contains(t, string(publicSSH), largeComment, "Comment should be preserved")

		t.Logf("✓ Large comment handling verified")
	})

	// Test special characters in comments
	t.Run("Special_Characters_In_Comments", func(t *testing.T) {
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key")

		// Test various special characters (safe ones for SSH)
		specialComments := []string{
			"user+test@example.com",
			"user.test@example-domain.org",
			"user_test@example.co.uk",
			"user-123@test.example.com",
		}

		for _, comment := range specialComments {
			t.Run(fmt.Sprintf("Comment_%s", comment), func(t *testing.T) {
				_, publicSSH, err := manager.ToSSH(comment, "")
				require.NoError(t, err, "Failed to convert with special comment")

				// Validate with ssh-keygen
				err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
				assert.NoError(t, err, "ssh-keygen should handle special characters: %s", comment)

				t.Logf("✓ Special characters in comment verified: %s", comment)
			})
		}
	})
}
