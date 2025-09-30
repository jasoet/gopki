package envelope

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/stretchr/testify/assert"
)

// Helper function to create test certificate
func createTestCertificate(t *testing.T, keyPair interface{}) *cert.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	var publicKey interface{}
	var privateKey interface{}

	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		publicKey = kp.PublicKey
		privateKey = kp.PrivateKey
	case *algo.ECDSAKeyPair:
		publicKey = kp.PublicKey
		privateKey = kp.PrivateKey
	case *algo.Ed25519KeyPair:
		publicKey = kp.PublicKey
		privateKey = kp.PrivateKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	assert.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	return &cert.Certificate{
		Certificate: parsedCert,
	}
}

// TestCertificateEnvelopeEncryptionWithCMSCycle tests the full cycle:
// EncryptWithCertificate() → EncodeData() → DecodeDataWithKey() → Decrypt()
//
// This test was missing and exposes a bug in DecodeFromCMS where it decrypts
// the data instead of preserving the encrypted envelope structure.
func TestCertificateEnvelopeEncryptionWithCMSCycle(t *testing.T) {
	testData := []byte("Test data for certificate-based envelope encryption with CMS encoding")

	t.Run("RSA Certificate - Full CMS Cycle", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		// Create test certificate
		testCert := createTestCertificate(t, rsaKeys)

		// Step 1: Encrypt with certificate (creates envelope encryption)
		opts := encryption.DefaultEncryptOptions()
		encrypted, err := EncryptWithCertificate(testData, testCert, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmEnvelope, encrypted.Algorithm)
		assert.NotNil(t, encrypted.Data, "Encrypted data should not be nil")
		assert.NotNil(t, encrypted.IV, "IV should not be nil for AES-GCM")
		assert.NotNil(t, encrypted.Tag, "Tag should not be nil for AES-GCM")
		assert.NotEmpty(t, encrypted.Recipients, "Recipients should not be empty")
		assert.NotNil(t, encrypted.Recipients[0].EncryptedKey, "EncryptedKey should not be nil")

		t.Logf("After encryption - Algorithm: %s, Data length: %d, IV length: %d, Tag length: %d",
			encrypted.Algorithm, len(encrypted.Data), len(encrypted.IV), len(encrypted.Tag))
		t.Logf("Recipient EncryptedKey length: %d", len(encrypted.Recipients[0].EncryptedKey))

		// Step 2: Encode to CMS format
		cmsData, err := encryption.EncodeData(encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, cmsData)
		assert.Greater(t, len(cmsData), 0, "CMS data should not be empty")

		t.Logf("CMS encoded data length: %d", len(cmsData))

		// Step 3: Decode from CMS format
		decoded, err := encryption.DecodeDataWithKey(cmsData, testCert.Certificate, rsaKeys.PrivateKey)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, encryption.AlgorithmEnvelope, decoded.Algorithm, "Algorithm should still be Envelope after decode")

		// CRITICAL CHECKS: Verify envelope structure is preserved
		t.Logf("After decode - Algorithm: %s, Data length: %d, IV length: %d, Tag length: %d",
			decoded.Algorithm, len(decoded.Data), len(decoded.IV), len(decoded.Tag))

		if len(decoded.Recipients) > 0 {
			t.Logf("After decode - Recipient EncryptedKey length: %d", len(decoded.Recipients[0].EncryptedKey))
		}

		// These assertions will FAIL with the current implementation:
		// The bug is that DecodeFromCMS decrypts the entire envelope,
		// so decoded.Data contains plaintext instead of AES-encrypted data
		assert.NotNil(t, decoded.IV, "IV should be preserved after CMS decode")
		assert.NotNil(t, decoded.Tag, "Tag should be preserved after CMS decode")
		assert.NotEmpty(t, decoded.Recipients, "Recipients should be preserved after CMS decode")

		if len(decoded.Recipients) > 0 {
			assert.NotNil(t, decoded.Recipients[0].EncryptedKey,
				"EncryptedKey should be preserved in recipient info after CMS decode")
		}

		// Step 4: Decrypt the envelope
		decrypted, err := Decrypt(decoded, rsaKeys, encryption.DefaultDecryptOptions())
		// This will FAIL with current implementation due to the bug
		if err != nil {
			t.Logf("Decryption failed (expected with bug): %v", err)
			t.Logf("This confirms the bug: DecodeFromCMS destroys envelope structure")
		}

		assert.NoError(t, err, "Decryption should succeed after CMS decode")
		assert.Equal(t, testData, decrypted, "Decrypted data should match original")
	})

	t.Run("Without CMS Cycle - Should Work", func(t *testing.T) {
		// This is the existing test that works (from envelope_test.go:486-501)
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)

		opts := encryption.DefaultEncryptOptions()
		encrypted, err := EncryptWithCertificate(testData, testCert, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmEnvelope, encrypted.Algorithm)

		// Decrypt WITHOUT CMS encode/decode cycle - this works!
		decrypted, err := Decrypt(encrypted, rsaKeys, encryption.DefaultDecryptOptions())
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)

		t.Log("Direct encrypt → decrypt works (no CMS encoding)")
	})
}

// TestCMSDecodePreservesEnvelopeStructure specifically tests that DecodeFromCMS
// preserves the envelope encryption structure instead of decrypting it
func TestCMSDecodePreservesEnvelopeStructure(t *testing.T) {
	testData := []byte("Test envelope structure preservation")

	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	assert.NoError(t, err)

	testCert := createTestCertificate(t, rsaKeys)

	// Create envelope encrypted data
	opts := encryption.DefaultEncryptOptions()
	encrypted, err := EncryptWithCertificate(testData, testCert, opts)
	assert.NoError(t, err)

	// Store original envelope metadata
	originalDataLen := len(encrypted.Data)
	originalIVLen := len(encrypted.IV)
	originalTagLen := len(encrypted.Tag)
	originalEncKeyLen := len(encrypted.Recipients[0].EncryptedKey)

	// Encode to CMS
	cmsData, err := encryption.EncodeData(encrypted)
	assert.NoError(t, err)

	// Decode from CMS
	decoded, err := encryption.DecodeDataWithKey(cmsData, testCert.Certificate, rsaKeys.PrivateKey)
	assert.NoError(t, err)

	// Verify structure preservation
	t.Run("Data should still be encrypted", func(t *testing.T) {
		// The decoded.Data should be AES-encrypted data, NOT plaintext
		// So it should NOT equal testData
		assert.NotEqual(t, testData, decoded.Data,
			"decoded.Data should be encrypted, not plaintext")

		// Data length should be similar (encrypted data length)
		assert.Equal(t, originalDataLen, len(decoded.Data),
			"Encrypted data length should be preserved")
	})

	t.Run("IV should be preserved", func(t *testing.T) {
		assert.NotNil(t, decoded.IV, "IV should not be nil")
		assert.Equal(t, originalIVLen, len(decoded.IV),
			"IV length should be preserved")
	})

	t.Run("Tag should be preserved", func(t *testing.T) {
		assert.NotNil(t, decoded.Tag, "Tag should not be nil")
		assert.Equal(t, originalTagLen, len(decoded.Tag),
			"Tag length should be preserved")
	})

	t.Run("Recipient info should be preserved", func(t *testing.T) {
		assert.NotEmpty(t, decoded.Recipients, "Recipients should not be empty")
		assert.NotNil(t, decoded.Recipients[0].EncryptedKey,
			"EncryptedKey should not be nil")
		assert.Equal(t, originalEncKeyLen, len(decoded.Recipients[0].EncryptedKey),
			"EncryptedKey length should be preserved")
	})
}

// TestOpenSSLCompatibleMode tests the OpenSSL-compatible encryption mode
func TestOpenSSLCompatibleMode(t *testing.T) {
	testData := []byte("Test data for OpenSSL-compatible envelope encryption")

	t.Run("RSA - OpenSSL Compatible Encrypt/Decrypt", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		// Create test certificate
		testCert := createTestCertificate(t, rsaKeys)

		// Enable OpenSSL-compatible mode
		opts := encryption.DefaultEncryptOptions()
		opts.OpenSSLCompatible = true

		// Encrypt with OpenSSL-compatible mode
		encrypted, err := EncryptWithCertificate(testData, testCert, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmEnvelope, encrypted.Algorithm)

		// Verify OpenSSL-compatible metadata flag
		assert.NotNil(t, encrypted.Metadata)
		isOpenSSL, ok := encrypted.Metadata["openssl_compatible"].(bool)
		assert.True(t, ok, "openssl_compatible metadata should be present")
		assert.True(t, isOpenSSL, "openssl_compatible should be true")

		// The Data field should contain raw PKCS#7 EnvelopedData
		assert.NotEmpty(t, encrypted.Data, "Data should contain PKCS#7 EnvelopedData")

		t.Logf("OpenSSL-compatible encrypted data length: %d", len(encrypted.Data))

		// Decrypt with OpenSSL-compatible mode
		decrypted, err := Decrypt(encrypted, rsaKeys, encryption.DefaultDecryptOptions())
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted, "Decrypted data should match original")

		t.Log("OpenSSL-compatible encrypt → decrypt successful")
	})

	t.Run("RSA - OpenSSL Compatible with CMS Cycle", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		// Create test certificate
		testCert := createTestCertificate(t, rsaKeys)

		// Enable OpenSSL-compatible mode
		opts := encryption.DefaultEncryptOptions()
		opts.OpenSSLCompatible = true

		// Step 1: Encrypt with OpenSSL-compatible mode
		encrypted, err := EncryptWithCertificate(testData, testCert, opts)
		assert.NoError(t, err)

		// Step 2: Encode to CMS (should just return the Data field)
		cmsData, err := encryption.EncodeData(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, encrypted.Data, cmsData, "CMS data should be the same as encrypted.Data for OpenSSL mode")

		t.Logf("OpenSSL-compatible CMS data length: %d", len(cmsData))

		// Step 3: Decode from CMS
		decoded, err := encryption.DecodeDataWithKey(cmsData, testCert.Certificate, rsaKeys.PrivateKey)
		assert.NoError(t, err)
		assert.Equal(t, encryption.AlgorithmEnvelope, decoded.Algorithm)

		// Verify already_decrypted flag
		alreadyDecrypted, ok := decoded.Metadata["already_decrypted"].(bool)
		assert.True(t, ok, "already_decrypted metadata should be present")
		assert.True(t, alreadyDecrypted, "already_decrypted should be true")

		// Step 4: Decrypt (should just return the data since it's already decrypted)
		decrypted, err := Decrypt(decoded, rsaKeys, encryption.DefaultDecryptOptions())
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted, "Decrypted data should match original")

		t.Log("OpenSSL-compatible full CMS cycle successful")
	})

	t.Run("ECDSA - OpenSSL Compatible Should Fail", func(t *testing.T) {
		// Generate ECDSA key pair
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		assert.NoError(t, err)

		// Create test certificate
		testCert := createTestCertificate(t, ecdsaKeys)

		// Enable OpenSSL-compatible mode
		opts := encryption.DefaultEncryptOptions()
		opts.OpenSSLCompatible = true

		// Should fail with ECDSA key
		encrypted, err := EncryptWithCertificate(testData, testCert, opts)
		assert.Error(t, err, "OpenSSL mode should fail with ECDSA key")
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "OpenSSL compatible mode requires RSA certificate")

		t.Log("OpenSSL-compatible mode correctly rejected ECDSA key")
	})

	t.Run("Ed25519 - OpenSSL Compatible Should Fail", func(t *testing.T) {
		// Generate Ed25519 key pair
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		assert.NoError(t, err)

		// Create test certificate
		testCert := createTestCertificate(t, ed25519Keys)

		// Enable OpenSSL-compatible mode
		opts := encryption.DefaultEncryptOptions()
		opts.OpenSSLCompatible = true

		// Should fail with Ed25519 key
		encrypted, err := EncryptWithCertificate(testData, testCert, opts)
		assert.Error(t, err, "OpenSSL mode should fail with Ed25519 key")
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "OpenSSL compatible mode requires RSA certificate")

		t.Log("OpenSSL-compatible mode correctly rejected Ed25519 key")
	})
}
