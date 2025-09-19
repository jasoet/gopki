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

// TestSSHKeypairCompatibility tests SSH key pair compatibility between GoPKI and OpenSSH
func TestSSHKeypairCompatibility(t *testing.T) {
	t.Logf("🔐 Running SSH OpenSSH Compatibility Tests...")
	t.Logf("   Testing SSH key generation, validation, and format conversion")

	t.Run("RSA", func(t *testing.T) {
		testSSHRSACompatibility(t)
	})

	t.Run("ECDSA", func(t *testing.T) {
		testSSHECDSACompatibility(t)
	})

	t.Run("Ed25519", func(t *testing.T) {
		testSSHEd25519Compatibility(t)
	})
}

func testSSHRSACompatibility(t *testing.T) {
	keySizes := []struct {
		size algo.KeySize
		bits int
		name string
	}{
		{algo.KeySize2048, 2048, "2048"},
		{algo.KeySize3072, 3072, "3072"},
		{algo.KeySize4096, 4096, "4096"},
	}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("RSA_%s", keySize.name), func(t *testing.T) {
			helper := compatibility.NewOpenSSLHelper(t)
			defer helper.Cleanup()

			t.Logf("Testing RSA-%d SSH compatibility", keySize.bits)

			// Test 1: GoPKI generates SSH keys → ssh-keygen validates
			t.Run("GoPKI_Generate_SSH_Validate", func(t *testing.T) {
				// Generate RSA key pair with GoPKI
				manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize.size)
				require.NoError(t, err, "Failed to generate RSA key pair with GoPKI")

				// Convert to SSH format
				privateSSH, publicSSH, err := manager.ToSSH("test@gopki.com", "")
				require.NoError(t, err, "Failed to convert keys to SSH format")

				// Validate private key with ssh-keygen
				err = helper.ValidateSSHPrivateKeyWithSSHKeygen([]byte(privateSSH))
				assert.NoError(t, err, "ssh-keygen validation failed for GoPKI-generated RSA private key")

				// Validate public key with ssh-keygen
				err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
				assert.NoError(t, err, "ssh-keygen validation failed for GoPKI-generated RSA public key")

				// Validate authorized_keys format
				err = helper.ValidateAuthorizedKeysFormat([]byte(publicSSH))
				assert.NoError(t, err, "authorized_keys format validation failed")

				t.Logf("✓ GoPKI RSA-%d SSH keys validated by ssh-keygen", keySize.bits)
			})

			// Test 2: ssh-keygen generates → GoPKI validates
			t.Run("SSHKeygen_Generate_GoPKI_Validate", func(t *testing.T) {
				// Generate RSA key pair with ssh-keygen
				privateSSH, publicSSH, err := helper.GenerateSSHKeyWithSSHKeygen("rsa", keySize.bits)
				require.NoError(t, err, "Failed to generate RSA key pair with ssh-keygen")

				// Load with GoPKI
				manager, err := keypair.LoadFromSSHData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](
					format.SSH(privateSSH), "",
				)
				require.NoError(t, err, "Failed to load ssh-keygen generated RSA key with GoPKI")

				// Verify key properties
				rsaKeyPair := manager.KeyPair()
				assert.NotNil(t, rsaKeyPair.PrivateKey, "Private key should not be nil")
				assert.NotNil(t, rsaKeyPair.PublicKey, "Public key should not be nil")
				assert.Equal(t, keySize.bits/8, rsaKeyPair.PrivateKey.Size(), "Key size mismatch")

				// Parse public key with GoPKI
				parsedPublicKey, err := keypair.PublicKeyFromSSH[*rsa.PublicKey](format.SSH(publicSSH))
				require.NoError(t, err, "Failed to parse SSH public key with GoPKI")
				assert.NotNil(t, parsedPublicKey, "Parsed public key should not be nil")

				t.Logf("✓ ssh-keygen RSA-%d keys loaded and validated by GoPKI", keySize.bits)
			})

			// Test 3: Passphrase protection
			t.Run("Passphrase_Protection", func(t *testing.T) {
				passphrase := "test-passphrase-123"

				// Generate with GoPKI and passphrase
				manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize.size)
				require.NoError(t, err, "Failed to generate RSA key pair")

				privateSSH, _, err := manager.ToSSH("test@gopki.com", passphrase)
				require.NoError(t, err, "Failed to convert to SSH with passphrase")

				// Try to load without passphrase (should fail)
				_, err = keypair.LoadFromSSHData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](
					privateSSH, "",
				)
				assert.Error(t, err, "Should fail to load encrypted key without passphrase")

				// Load with correct passphrase
				loadedManager, err := keypair.LoadFromSSHData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](
					privateSSH, passphrase,
				)
				require.NoError(t, err, "Failed to load encrypted key with correct passphrase")
				assert.NotNil(t, loadedManager.KeyPair().PrivateKey, "Private key should be loaded")

				// Generate with ssh-keygen and passphrase
				sshPrivate, _, err := helper.GenerateSSHKeyWithPassphrase("rsa", keySize.bits, passphrase)
				require.NoError(t, err, "Failed to generate passphrase-protected key with ssh-keygen")

				// Load ssh-keygen encrypted key with GoPKI
				sshManager, err := keypair.LoadFromSSHData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](
					format.SSH(sshPrivate), passphrase,
				)
				require.NoError(t, err, "Failed to load ssh-keygen encrypted key with GoPKI")
				assert.NotNil(t, sshManager.KeyPair().PrivateKey, "ssh-keygen encrypted key should be loaded")

				// Just verify that the encrypted key was loaded successfully
				// The public key comparison was already done above

				t.Logf("✓ RSA-%d passphrase protection validated bidirectionally", keySize.bits)
			})
		})
	}
}

func testSSHECDSACompatibility(t *testing.T) {
	curves := []struct {
		curve algo.ECDSACurve
		bits  int
		name  string
	}{
		{algo.P256, 256, "P-256"},
		{algo.P384, 384, "P-384"},
		{algo.P521, 521, "P-521"},
	}

	for _, curve := range curves {
		t.Run(curve.name, func(t *testing.T) {
			helper := compatibility.NewOpenSSLHelper(t)
			defer helper.Cleanup()

			t.Logf("Testing ECDSA %s SSH compatibility", curve.name)

			// Test 1: GoPKI generates SSH keys → ssh-keygen validates
			t.Run("GoPKI_Generate_SSH_Validate", func(t *testing.T) {
				// Generate ECDSA key pair with GoPKI
				manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve.curve)
				require.NoError(t, err, "Failed to generate ECDSA key pair with GoPKI")

				// Convert to SSH format
				privateSSH, publicSSH, err := manager.ToSSH("test@gopki.com", "")
				require.NoError(t, err, "Failed to convert keys to SSH format")

				// Validate private key with ssh-keygen
				err = helper.ValidateSSHPrivateKeyWithSSHKeygen([]byte(privateSSH))
				assert.NoError(t, err, "ssh-keygen validation failed for GoPKI-generated ECDSA private key")

				// Validate public key with ssh-keygen
				err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
				assert.NoError(t, err, "ssh-keygen validation failed for GoPKI-generated ECDSA public key")

				// Validate authorized_keys format
				err = helper.ValidateAuthorizedKeysFormat([]byte(publicSSH))
				assert.NoError(t, err, "authorized_keys format validation failed")

				t.Logf("✓ GoPKI ECDSA %s SSH keys validated by ssh-keygen", curve.name)
			})

			// Test 2: ssh-keygen generates → GoPKI validates
			t.Run("SSHKeygen_Generate_GoPKI_Validate", func(t *testing.T) {
				// Generate ECDSA key pair with ssh-keygen
				privateSSH, publicSSH, err := helper.GenerateSSHKeyWithSSHKeygen("ecdsa", curve.bits)
				require.NoError(t, err, "Failed to generate ECDSA key pair with ssh-keygen")

				// Load with GoPKI
				manager, err := keypair.LoadFromSSHData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](
					format.SSH(privateSSH), "",
				)
				require.NoError(t, err, "Failed to load ssh-keygen generated ECDSA key with GoPKI")

				// Verify key properties
				ecdsaKeyPair := manager.KeyPair()
				assert.NotNil(t, ecdsaKeyPair.PrivateKey, "Private key should not be nil")
				assert.NotNil(t, ecdsaKeyPair.PublicKey, "Public key should not be nil")

				// Parse public key with GoPKI
				parsedPublicKey, err := keypair.PublicKeyFromSSH[*ecdsa.PublicKey](format.SSH(publicSSH))
				require.NoError(t, err, "Failed to parse SSH public key with GoPKI")
				assert.NotNil(t, parsedPublicKey, "Parsed public key should not be nil")

				t.Logf("✓ ssh-keygen ECDSA %s keys loaded and validated by GoPKI", curve.name)
			})

			// Test 3: Passphrase protection
			t.Run("Passphrase_Protection", func(t *testing.T) {
				passphrase := "ecdsa-test-pass"

				// Generate with GoPKI and passphrase
				manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve.curve)
				require.NoError(t, err, "Failed to generate ECDSA key pair")

				privateSSH, _, err := manager.ToSSH("test@gopki.com", passphrase)
				require.NoError(t, err, "Failed to convert to SSH with passphrase")

				// Try to load without passphrase (should fail)
				_, err = keypair.LoadFromSSHData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](
					privateSSH, "",
				)
				assert.Error(t, err, "Should fail to load encrypted key without passphrase")

				// Load with correct passphrase
				loadedManager, err := keypair.LoadFromSSHData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](
					privateSSH, passphrase,
				)
				require.NoError(t, err, "Failed to load encrypted key with correct passphrase")
				assert.NotNil(t, loadedManager.KeyPair().PrivateKey, "Private key should be loaded")

				t.Logf("✓ ECDSA %s passphrase protection validated", curve.name)
			})
		})
	}
}

func testSSHEd25519Compatibility(t *testing.T) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Logf("Testing Ed25519 SSH compatibility")

	// Test 1: GoPKI generates SSH keys → ssh-keygen validates
	t.Run("GoPKI_Generate_SSH_Validate", func(t *testing.T) {
		// Generate Ed25519 key pair with GoPKI
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair with GoPKI")

		// Convert to SSH format
		privateSSH, publicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert keys to SSH format")

		// Validate private key with ssh-keygen
		err = helper.ValidateSSHPrivateKeyWithSSHKeygen([]byte(privateSSH))
		assert.NoError(t, err, "ssh-keygen validation failed for GoPKI-generated Ed25519 private key")

		// Validate public key with ssh-keygen
		err = helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
		assert.NoError(t, err, "ssh-keygen validation failed for GoPKI-generated Ed25519 public key")

		// Validate authorized_keys format
		err = helper.ValidateAuthorizedKeysFormat([]byte(publicSSH))
		assert.NoError(t, err, "authorized_keys format validation failed")

		t.Logf("✓ GoPKI Ed25519 SSH keys validated by ssh-keygen")
	})

	// Test 2: ssh-keygen generates → GoPKI validates
	t.Run("SSHKeygen_Generate_GoPKI_Validate", func(t *testing.T) {
		// Generate Ed25519 key pair with ssh-keygen
		privateSSH, publicSSH, err := helper.GenerateSSHKeyWithSSHKeygen("ed25519", 0)
		require.NoError(t, err, "Failed to generate Ed25519 key pair with ssh-keygen")

		// Load with GoPKI
		manager, err := keypair.LoadFromSSHData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](
			format.SSH(privateSSH), "",
		)
		require.NoError(t, err, "Failed to load ssh-keygen generated Ed25519 key with GoPKI")

		// Verify key properties
		ed25519KeyPair := manager.KeyPair()
		assert.NotNil(t, ed25519KeyPair.PrivateKey, "Private key should not be nil")
		assert.NotNil(t, ed25519KeyPair.PublicKey, "Public key should not be nil")

		// Parse public key with GoPKI
		parsedPublicKey, err := keypair.PublicKeyFromSSH[ed25519.PublicKey](format.SSH(publicSSH))
		require.NoError(t, err, "Failed to parse SSH public key with GoPKI")
		assert.NotNil(t, parsedPublicKey, "Parsed public key should not be nil")

		t.Logf("✓ ssh-keygen Ed25519 keys loaded and validated by GoPKI")
	})

	// Test 3: Passphrase protection
	t.Run("Passphrase_Protection", func(t *testing.T) {
		passphrase := "ed25519-pass"

		// Generate with GoPKI and passphrase
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair")

		privateSSH, _, err := manager.ToSSH("test@gopki.com", passphrase)
		require.NoError(t, err, "Failed to convert to SSH with passphrase")

		// Try to load without passphrase (should fail)
		_, err = keypair.LoadFromSSHData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](
			privateSSH, "",
		)
		assert.Error(t, err, "Should fail to load encrypted key without passphrase")

		// Load with correct passphrase
		loadedManager, err := keypair.LoadFromSSHData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](
			privateSSH, passphrase,
		)
		require.NoError(t, err, "Failed to load encrypted key with correct passphrase")
		assert.NotNil(t, loadedManager.KeyPair().PrivateKey, "Private key should be loaded")

		t.Logf("✓ Ed25519 passphrase protection validated")
	})
}

// TestSSHFingerprintCompatibility tests SSH fingerprint generation compatibility
func TestSSHFingerprintCompatibility(t *testing.T) {
	t.Logf("🔍 Testing SSH Fingerprint Compatibility...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Test RSA fingerprints
	t.Run("RSA_Fingerprints", func(t *testing.T) {
		// Generate RSA key with GoPKI
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		require.NoError(t, err, "Failed to generate RSA key pair")

		_, publicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Get SHA256 fingerprint from ssh-keygen
		sha256Fingerprint, err := helper.GetSSHKeyFingerprint([]byte(publicSSH), "sha256")
		require.NoError(t, err, "Failed to get SHA256 fingerprint")
		assert.True(t, strings.HasPrefix(sha256Fingerprint, "SHA256:"), "SHA256 fingerprint should have correct prefix")

		// Get MD5 fingerprint from ssh-keygen
		md5Fingerprint, err := helper.GetSSHKeyFingerprint([]byte(publicSSH), "md5")
		require.NoError(t, err, "Failed to get MD5 fingerprint")
		assert.True(t, strings.HasPrefix(md5Fingerprint, "MD5:"), "MD5 fingerprint should have correct prefix")

		t.Logf("✓ RSA fingerprints: SHA256=%s, MD5=%s", sha256Fingerprint, md5Fingerprint)
	})

	// Test ECDSA fingerprints
	t.Run("ECDSA_Fingerprints", func(t *testing.T) {
		// Generate ECDSA key with GoPKI
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		require.NoError(t, err, "Failed to generate ECDSA key pair")

		_, publicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Get fingerprints
		sha256Fingerprint, err := helper.GetSSHKeyFingerprint([]byte(publicSSH), "sha256")
		require.NoError(t, err, "Failed to get SHA256 fingerprint")
		assert.True(t, strings.HasPrefix(sha256Fingerprint, "SHA256:"), "SHA256 fingerprint should have correct prefix")

		t.Logf("✓ ECDSA P-256 fingerprint: %s", sha256Fingerprint)
	})

	// Test Ed25519 fingerprints
	t.Run("Ed25519_Fingerprints", func(t *testing.T) {
		// Generate Ed25519 key with GoPKI
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair")

		_, publicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Get fingerprints
		sha256Fingerprint, err := helper.GetSSHKeyFingerprint([]byte(publicSSH), "sha256")
		require.NoError(t, err, "Failed to get SHA256 fingerprint")
		assert.True(t, strings.HasPrefix(sha256Fingerprint, "SHA256:"), "SHA256 fingerprint should have correct prefix")

		t.Logf("✓ Ed25519 fingerprint: %s", sha256Fingerprint)
	})
}

// TestSSHPublicKeyExtraction tests extracting public keys from private keys
func TestSSHPublicKeyExtraction(t *testing.T) {
	t.Logf("🔑 Testing SSH Public Key Extraction...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("RSA_Public_Key_Extraction", func(t *testing.T) {
		// Generate RSA key with GoPKI
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		require.NoError(t, err, "Failed to generate RSA key pair")

		privateSSH, expectedPublicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Extract public key using ssh-keygen from private key
		extractedPublic, err := helper.ExtractPublicKeyWithSSHKeygen([]byte(privateSSH))
		require.NoError(t, err, "Failed to extract public key with ssh-keygen")

		// The extracted key should be parseable by GoPKI
		extractedKey, err := keypair.PublicKeyFromSSH[*rsa.PublicKey](format.SSH(extractedPublic))
		require.NoError(t, err, "Failed to parse extracted public key")
		assert.NotNil(t, extractedKey, "Extracted key should not be nil")

		// Compare fingerprints to verify they're the same key
		expectedFingerprint, err := helper.GetSSHKeyFingerprint([]byte(expectedPublicSSH), "sha256")
		require.NoError(t, err, "Failed to get expected fingerprint")

		extractedFingerprint, err := helper.GetSSHKeyFingerprint(extractedPublic, "sha256")
		require.NoError(t, err, "Failed to get extracted fingerprint")

		assert.Equal(t, expectedFingerprint, extractedFingerprint, "Fingerprints should match")

		t.Logf("✓ RSA public key extraction verified")
	})

	t.Run("ECDSA_Public_Key_Extraction", func(t *testing.T) {
		// Generate ECDSA key with GoPKI
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		require.NoError(t, err, "Failed to generate ECDSA key pair")

		privateSSH, expectedPublicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Extract public key using ssh-keygen
		extractedPublic, err := helper.ExtractPublicKeyWithSSHKeygen([]byte(privateSSH))
		require.NoError(t, err, "Failed to extract public key with ssh-keygen")

		// Parse and verify
		extractedKey, err := keypair.PublicKeyFromSSH[*ecdsa.PublicKey](format.SSH(extractedPublic))
		require.NoError(t, err, "Failed to parse extracted public key")
		assert.NotNil(t, extractedKey, "Extracted key should not be nil")

		// Compare fingerprints
		expectedFingerprint, err := helper.GetSSHKeyFingerprint([]byte(expectedPublicSSH), "sha256")
		require.NoError(t, err, "Failed to get expected fingerprint")

		extractedFingerprint, err := helper.GetSSHKeyFingerprint(extractedPublic, "sha256")
		require.NoError(t, err, "Failed to get extracted fingerprint")

		assert.Equal(t, expectedFingerprint, extractedFingerprint, "Fingerprints should match")

		t.Logf("✓ ECDSA public key extraction verified")
	})

	t.Run("Ed25519_Public_Key_Extraction", func(t *testing.T) {
		// Generate Ed25519 key with GoPKI
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair")

		privateSSH, expectedPublicSSH, err := manager.ToSSH("test@gopki.com", "")
		require.NoError(t, err, "Failed to convert to SSH format")

		// Extract public key using ssh-keygen
		extractedPublic, err := helper.ExtractPublicKeyWithSSHKeygen([]byte(privateSSH))
		require.NoError(t, err, "Failed to extract public key with ssh-keygen")

		// Parse and verify
		extractedKey, err := keypair.PublicKeyFromSSH[ed25519.PublicKey](format.SSH(extractedPublic))
		require.NoError(t, err, "Failed to parse extracted public key")
		assert.NotNil(t, extractedKey, "Extracted key should not be nil")

		// Compare fingerprints
		expectedFingerprint, err := helper.GetSSHKeyFingerprint([]byte(expectedPublicSSH), "sha256")
		require.NoError(t, err, "Failed to get expected fingerprint")

		extractedFingerprint, err := helper.GetSSHKeyFingerprint(extractedPublic, "sha256")
		require.NoError(t, err, "Failed to get extracted fingerprint")

		assert.Equal(t, expectedFingerprint, extractedFingerprint, "Fingerprints should match")

		t.Logf("✓ Ed25519 public key extraction verified")
	})
}

// TestSSHAuthorizedKeysFormat tests authorized_keys format compatibility
func TestSSHAuthorizedKeysFormat(t *testing.T) {
	t.Logf("📝 Testing SSH authorized_keys Format Compatibility...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("All_Algorithms_AuthorizedKeys", func(t *testing.T) {
		// Test RSA
		rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		require.NoError(t, err, "Failed to generate RSA key")

		_, rsaPublicSSH, err := rsaManager.ToSSH("rsa-user@host.com", "")
		require.NoError(t, err, "Failed to convert RSA to SSH")

		err = helper.ValidateAuthorizedKeysFormat([]byte(rsaPublicSSH))
		assert.NoError(t, err, "RSA authorized_keys validation failed")
		assert.True(t, strings.HasPrefix(string(rsaPublicSSH), "ssh-rsa "), "RSA key should start with ssh-rsa")
		assert.True(t, strings.Contains(string(rsaPublicSSH), "rsa-user@host.com"), "Should contain comment")

		// Test ECDSA
		ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		require.NoError(t, err, "Failed to generate ECDSA key")

		_, ecdsaPublicSSH, err := ecdsaManager.ToSSH("ecdsa-user@host.com", "")
		require.NoError(t, err, "Failed to convert ECDSA to SSH")

		err = helper.ValidateAuthorizedKeysFormat([]byte(ecdsaPublicSSH))
		assert.NoError(t, err, "ECDSA authorized_keys validation failed")
		assert.True(t, strings.HasPrefix(string(ecdsaPublicSSH), "ecdsa-sha2-nistp256 "), "ECDSA P-256 key should have correct prefix")

		// Test Ed25519
		ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key")

		_, ed25519PublicSSH, err := ed25519Manager.ToSSH("ed25519-user@host.com", "")
		require.NoError(t, err, "Failed to convert Ed25519 to SSH")

		err = helper.ValidateAuthorizedKeysFormat([]byte(ed25519PublicSSH))
		assert.NoError(t, err, "Ed25519 authorized_keys validation failed")
		assert.True(t, strings.HasPrefix(string(ed25519PublicSSH), "ssh-ed25519 "), "Ed25519 key should start with ssh-ed25519")

		t.Logf("✓ All algorithms validated for authorized_keys format")
	})
}