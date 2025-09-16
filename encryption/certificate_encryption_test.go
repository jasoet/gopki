package encryption

import (
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestCertificateEncryptor(t *testing.T) {
	encryptor := NewCertificateEncryptor()
	data := []byte("Certificate encryption test data")

	// Helper function to create a test certificate
	createTestCertificate := func(keyPair any) *cert.Certificate {
		t.Helper()
		request := cert.CertificateRequest{
			Subject:  pkix.Name{CommonName: "Test Certificate"},
			ValidFor: 24 * time.Hour,
		}

		var certificate *cert.Certificate
		var err error

		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(kp, request)
		case *algo.ECDSAKeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(kp, request)
		case *algo.Ed25519KeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(kp, request)
		default:
			t.Fatalf("Unsupported key pair type: %T", keyPair)
		}

		if err != nil {
			t.Fatalf("Failed to create test certificate: %v", err)
		}
		return certificate
	}

	t.Run("EncryptDocument RSA", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		certificate := createTestCertificate(rsaKeys)

		encrypted, err := encryptor.EncryptDocument(data, certificate, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt document: %v", err)
		}

		if encrypted.Algorithm != AlgorithmEnvelope {
			t.Errorf("Expected envelope algorithm, got %s", encrypted.Algorithm)
		}

		decrypted, err := encryptor.DecryptDocument(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt document: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("EncryptDocument ECDSA", func(t *testing.T) {
		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		certificate := createTestCertificate(ecdsaKeys)

		encrypted, err := encryptor.EncryptDocument(data, certificate, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt document: %v", err)
		}

		decrypted, err := encryptor.DecryptDocument(encrypted, ecdsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt document: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("EncryptDocument Ed25519 - Should Fail", func(t *testing.T) {
		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		certificate := createTestCertificate(ed25519Keys)

		// Ed25519 public-key-only encryption is not supported, should return an error
		_, err = encryptor.EncryptDocument(data, certificate, DefaultEncryptOptions())
		if err == nil {
			t.Fatal("Expected error for Ed25519 public-key-only encryption, but got none")
		}

		// Verify we get the expected error message
		expectedError := "Ed25519 public-key-only encryption not supported"
		if !strings.Contains(err.Error(), expectedError) {
			t.Errorf("Expected error containing '%s', got: %v", expectedError, err)
		}
	})

	t.Run("EncryptForMultipleCertificates", func(t *testing.T) {
		// Generate multiple key pairs and certificates
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		certificates := []*cert.Certificate{
			createTestCertificate(rsaKeys),
			createTestCertificate(ecdsaKeys),
		}

		encrypted, err := encryptor.EncryptForMultipleCertificates(data, certificates, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt for multiple certificates: %v", err)
		}

		// Test decryption with first certificate holder
		decrypted1, err := encryptor.DecryptForCertificateHolder(encrypted, rsaKeys, 0, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt for first certificate holder: %v", err)
		}

		if string(decrypted1) != string(data) {
			t.Error("First certificate holder decryption failed")
		}

		// Test decryption with second certificate holder
		decrypted2, err := encryptor.DecryptForCertificateHolder(encrypted, ecdsaKeys, 1, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt for second certificate holder: %v", err)
		}

		if string(decrypted2) != string(data) {
			t.Error("Second certificate holder decryption failed")
		}
	})

	t.Run("IncludeCertificate Option", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		certificate := createTestCertificate(rsaKeys)

		opts := DefaultEncryptOptions()
		opts.IncludeCertificate = true

		encrypted, err := encryptor.EncryptDocument(data, certificate, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt document: %v", err)
		}

		if len(encrypted.Recipients) == 0 {
			t.Error("Expected recipients to be set when IncludeCertificate is true")
		}

		if encrypted.Recipients[0].Certificate == nil {
			t.Error("Expected certificate to be included in recipient info")
		}
	})

	t.Run("FindRecipientByCertificate", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		certificates := []*cert.Certificate{
			createTestCertificate(rsaKeys),
			createTestCertificate(ecdsaKeys),
		}

		opts := DefaultEncryptOptions()
		opts.IncludeCertificate = true

		encrypted, err := encryptor.EncryptForMultipleCertificates(data, certificates, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt for multiple certificates: %v", err)
		}

		// Find first certificate
		index, err := encryptor.FindRecipientByCertificate(encrypted, certificates[0])
		if err != nil {
			t.Fatalf("Failed to find first certificate: %v", err)
		}

		if index != 0 {
			t.Errorf("Expected index 0, got %d", index)
		}

		// Find second certificate
		index, err = encryptor.FindRecipientByCertificate(encrypted, certificates[1])
		if err != nil {
			t.Fatalf("Failed to find second certificate: %v", err)
		}

		if index != 1 {
			t.Errorf("Expected index 1, got %d", index)
		}

		// Try to find non-existent certificate
		nonExistentCert := createTestCertificate(rsaKeys) // Different certificate
		_, err = encryptor.FindRecipientByCertificate(encrypted, nonExistentCert)
		if err == nil {
			t.Error("Expected error for non-existent certificate")
		}
	})

	t.Run("Error Cases", func(t *testing.T) {
		// Nil certificate
		_, err := encryptor.EncryptDocument(data, nil, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for nil certificate")
		}

		// Nil encrypted data for decryption
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		_, err = encryptor.DecryptDocument(nil, rsaKeys, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for nil encrypted data")
		}

		// Empty certificates array
		_, err = encryptor.EncryptForMultipleCertificates(data, []*cert.Certificate{}, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for empty certificates array")
		}

		// Nil certificate in array
		certificates := []*cert.Certificate{nil}
		_, err = encryptor.EncryptForMultipleCertificates(data, certificates, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for nil certificate in array")
		}

		// FindRecipientByCertificate with nil inputs
		_, err = encryptor.FindRecipientByCertificate(nil, nil)
		if err == nil {
			t.Error("Expected error for nil encrypted data in FindRecipientByCertificate")
		}

		encrypted := &EncryptedData{}
		_, err = encryptor.FindRecipientByCertificate(encrypted, nil)
		if err == nil {
			t.Error("Expected error for nil certificate in FindRecipientByCertificate")
		}
	})

	t.Run("SupportedAlgorithms", func(t *testing.T) {
		algorithms := encryptor.SupportedAlgorithms()
		expected := []EncryptionAlgorithm{
			AlgorithmEnvelope,
			AlgorithmAESGCM,
			AlgorithmRSAOAEP,
			AlgorithmECDH,
			AlgorithmX25519,
		}

		if len(algorithms) != len(expected) {
			t.Errorf("Expected %d algorithms, got %d", len(algorithms), len(expected))
		}

		for _, alg := range expected {
			found := false
			for _, supported := range algorithms {
				if supported == alg {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Algorithm %s should be supported", alg)
			}
		}
	})
}

func TestCertificateHelperFunctions(t *testing.T) {
	t.Run("getCertificateKeyType", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		request := cert.CertificateRequest{
			Subject:  pkix.Name{CommonName: "Test Certificate"},
			ValidFor: 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(rsaKeys, request)
		if err != nil {
			t.Fatalf("Failed to create test certificate: %v", err)
		}

		keyType := getCertificateKeyType(certificate)
		if keyType != "RSA" {
			t.Errorf("Expected RSA key type, got %s", keyType)
		}
	})

	t.Run("validateCertificateForEncryption", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Create a standard certificate (the cert package sets appropriate key usage by default)
		request := cert.CertificateRequest{
			Subject:  pkix.Name{CommonName: "Test Certificate"},
			ValidFor: 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(rsaKeys, request)
		if err != nil {
			t.Fatalf("Failed to create test certificate: %v", err)
		}

		// This should pass validation (the default cert has appropriate key usage)
		err = validateCertificateForEncryption(certificate)
		if err != nil {
			t.Errorf("Certificate validation should pass: %v", err)
		}
	})

	t.Run("validateCertificateForDecryption", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Create a standard certificate
		request := cert.CertificateRequest{
			Subject:  pkix.Name{CommonName: "Test Certificate"},
			ValidFor: 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(rsaKeys, request)
		if err != nil {
			t.Fatalf("Failed to create test certificate: %v", err)
		}

		// This should pass validation
		err = validateCertificateForDecryption(certificate)
		if err != nil {
			t.Errorf("Certificate validation should pass: %v", err)
		}
	})
}
