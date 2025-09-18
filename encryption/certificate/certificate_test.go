package certificate

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
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
	default:
		t.Fatalf("Unsupported key pair type: %T", keyPair)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	assert.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	return &cert.Certificate{
		Certificate: parsedCert,
	}
}

// Helper function to create expired certificate
func createExpiredCertificate(t *testing.T, keyPair interface{}) *cert.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Expired Certificate",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	var publicKey interface{}
	var privateKey interface{}

	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		publicKey = kp.PublicKey
		privateKey = kp.PrivateKey
	default:
		t.Fatalf("Unsupported key pair type: %T", keyPair)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	assert.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	return &cert.Certificate{
		Certificate: parsedCert,
	}
}

// Helper function to create certificate without encryption key usage
func createNonEncryptionCertificate(t *testing.T, keyPair interface{}) *cert.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Non-Encryption Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature, // No KeyEncipherment or KeyAgreement
		BasicConstraintsValid: true,
	}

	var publicKey interface{}
	var privateKey interface{}

	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		publicKey = kp.PublicKey
		privateKey = kp.PrivateKey
	default:
		t.Fatalf("Unsupported key pair type: %T", keyPair)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	assert.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	return &cert.Certificate{
		Certificate: parsedCert,
	}
}

func TestEncryptDocument(t *testing.T) {
	testData := []byte("test document for encryption")
	opts := encryption.DefaultEncryptOptions()

	t.Run("RSA Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)

		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.NotEmpty(t, encrypted.Data)
	})

	t.Run("ECDSA Certificate", func(t *testing.T) {
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, ecdsaKeys)

		// ECDSA is not yet supported for public key encryption
		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "EncryptForPublicKey not yet implemented for *ecdsa.PublicKey")
	})

	t.Run("Ed25519 Certificate", func(t *testing.T) {
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		assert.NoError(t, err)

		testCert := createTestCertificate(t, ed25519Keys)

		// Ed25519 is not yet supported for public key encryption
		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "EncryptForPublicKey not yet implemented for ed25519.PublicKey")
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		encrypted, err := EncryptDocument(testData, nil, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "certificate is required")
	})

	t.Run("With Certificate Metadata", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)

		opts := encryption.DefaultEncryptOptions()
		opts.IncludeCertificate = true

		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.NotNil(t, encrypted.Metadata)
		assert.Contains(t, encrypted.Metadata, "certificate_subject")
		assert.Contains(t, encrypted.Metadata, "certificate_serial")
	})
}

func TestDecryptDocument(t *testing.T) {
	testData := []byte("test document for decryption")
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	t.Run("RSA Round Trip", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)

		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptDocument(encrypted, rsaKeys, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("ECDSA Round Trip", func(t *testing.T) {
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, ecdsaKeys)

		// ECDSA is not yet supported for public key encryption
		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "EncryptForPublicKey not yet implemented for *ecdsa.PublicKey")
	})

	t.Run("Ed25519 Round Trip", func(t *testing.T) {
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		assert.NoError(t, err)

		testCert := createTestCertificate(t, ed25519Keys)

		// Ed25519 is not yet supported for public key encryption
		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "EncryptForPublicKey not yet implemented for ed25519.PublicKey")
	})

	t.Run("Nil Encrypted Data", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		decrypted, err := DecryptDocument[*algo.RSAKeyPair](nil, rsaKeys, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "encrypted data is required")
	})
}

func TestEncryptForMultipleCertificates(t *testing.T) {
	testData := []byte("test document for multiple recipients")
	opts := encryption.DefaultEncryptOptions()

	t.Run("Multiple RSA Certificates", func(t *testing.T) {
		// Generate multiple key pairs
		rsaKeys1, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)
		rsaKeys2, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)
		rsaKeys3, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		// Create certificates
		cert1 := createTestCertificate(t, rsaKeys1)
		cert2 := createTestCertificate(t, rsaKeys2)
		cert3 := createTestCertificate(t, rsaKeys3)

		certificates := []*cert.Certificate{cert1, cert2, cert3}

		encrypted, err := EncryptForMultipleCertificates(testData, certificates, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.NotEmpty(t, encrypted.Data)
		assert.Len(t, encrypted.Recipients, 3)
	})

	t.Run("Mixed Key Types", func(t *testing.T) {
		rsaKeys1, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)
		rsaKeys2, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		cert1 := createTestCertificate(t, rsaKeys1)
		cert2 := createTestCertificate(t, rsaKeys2)

		// Only use RSA certificates since ECDSA and Ed25519 are not yet supported
		certificates := []*cert.Certificate{cert1, cert2}

		encrypted, err := EncryptForMultipleCertificates(testData, certificates, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Len(t, encrypted.Recipients, 2)
	})

	t.Run("Empty Certificate List", func(t *testing.T) {
		encrypted, err := EncryptForMultipleCertificates(testData, []*cert.Certificate{}, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "at least one certificate is required")
	})

	t.Run("Nil Certificate in List", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		cert1 := createTestCertificate(t, rsaKeys)
		certificates := []*cert.Certificate{cert1, nil}

		encrypted, err := EncryptForMultipleCertificates(testData, certificates, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "certificate at index 1 is nil")
	})

	t.Run("With Recipient Metadata", func(t *testing.T) {
		rsaKeys1, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)
		rsaKeys2, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		cert1 := createTestCertificate(t, rsaKeys1)
		cert2 := createTestCertificate(t, rsaKeys2)

		certificates := []*cert.Certificate{cert1, cert2}

		opts := encryption.DefaultEncryptOptions()
		opts.IncludeCertificate = true

		encrypted, err := EncryptForMultipleCertificates(testData, certificates, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted.Metadata)
		assert.Contains(t, encrypted.Metadata, "recipient_subjects")
	})
}

func TestDecryptForCertificateHolder(t *testing.T) {
	testData := []byte("test document for multiple recipients")
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	t.Run("Decrypt by Different Recipients", func(t *testing.T) {
		// Generate multiple key pairs
		rsaKeys1, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)
		rsaKeys2, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)
		rsaKeys3, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		// Create certificates
		cert1 := createTestCertificate(t, rsaKeys1)
		cert2 := createTestCertificate(t, rsaKeys2)
		cert3 := createTestCertificate(t, rsaKeys3)

		certificates := []*cert.Certificate{cert1, cert2, cert3}

		encrypted, err := EncryptForMultipleCertificates(testData, certificates, opts)
		assert.NoError(t, err)

		// Each recipient should be able to decrypt
		decrypted1, err := DecryptForCertificateHolder(encrypted, rsaKeys1, 0, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted1)

		decrypted2, err := DecryptForCertificateHolder(encrypted, rsaKeys2, 1, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted2)

		decrypted3, err := DecryptForCertificateHolder(encrypted, rsaKeys3, 2, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted3)
	})

	t.Run("Invalid Recipient Index", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		cert := createTestCertificate(t, rsaKeys)
		encrypted, err := EncryptDocument(testData, cert, opts)
		assert.NoError(t, err)

		// Try to decrypt with invalid index
		decrypted, err := DecryptForCertificateHolder(encrypted, rsaKeys, 5, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("Nil Encrypted Data", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		decrypted, err := DecryptForCertificateHolder[*algo.RSAKeyPair](nil, rsaKeys, 0, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "encrypted data is required")
	})
}

func TestEncryptWithKeyUsageValidation(t *testing.T) {
	testData := []byte("test document with validation")
	opts := encryption.DefaultEncryptOptions()

	t.Run("Valid Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)

		encrypted, err := EncryptWithKeyUsageValidation(testData, testCert, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
	})

	t.Run("Expired Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		expiredCert := createExpiredCertificate(t, rsaKeys)

		encrypted, err := EncryptWithKeyUsageValidation(testData, expiredCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "certificate has expired")
	})

	t.Run("Certificate Without Encryption Key Usage", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		nonEncryptCert := createNonEncryptionCertificate(t, rsaKeys)

		encrypted, err := EncryptWithKeyUsageValidation(testData, nonEncryptCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "key usage does not allow encryption")
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		encrypted, err := EncryptWithKeyUsageValidation(testData, nil, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "certificate is required")
	})

	t.Run("Not Yet Valid Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		template := x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Future Certificate"},
			NotBefore:             time.Now().Add(24 * time.Hour), // Future
			NotAfter:              time.Now().Add(48 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
			rsaKeys.PublicKey, rsaKeys.PrivateKey)
		assert.NoError(t, err)

		parsedCert, err := x509.ParseCertificate(certDER)
		assert.NoError(t, err)

		futureCert := &cert.Certificate{
			Certificate: parsedCert,
		}

		encrypted, err := EncryptWithKeyUsageValidation(testData, futureCert, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "certificate is not yet valid")
	})
}

func TestDecryptWithCertificateValidation(t *testing.T) {
	testData := []byte("test document with validation")
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	t.Run("Valid Certificate and KeyPair", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)

		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptWithCertificateValidation(encrypted, rsaKeys, testCert, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)
		encrypted, err := EncryptDocument(testData, testCert, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptWithCertificateValidation(encrypted, rsaKeys, nil, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "certificate is required")
	})
}

func TestValidateCertificateForEncryption(t *testing.T) {
	t.Run("Valid Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)
		err = validateCertificateForEncryption(testCert)
		assert.NoError(t, err)
	})

	t.Run("Certificate Without Key Usage", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		template := x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "No Key Usage"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			// KeyUsage not set (zero value)
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
			rsaKeys.PublicKey, rsaKeys.PrivateKey)
		assert.NoError(t, err)

		parsedCert, err := x509.ParseCertificate(certDER)
		assert.NoError(t, err)

		cert := &cert.Certificate{
			Certificate: parsedCert,
		}

		// Should pass because KeyUsage is 0 (not set)
		err = validateCertificateForEncryption(cert)
		assert.NoError(t, err)
	})

	t.Run("Certificate With Wrong Key Usage", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		nonEncryptCert := createNonEncryptionCertificate(t, rsaKeys)
		err = validateCertificateForEncryption(nonEncryptCert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key usage does not allow encryption")
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		err := validateCertificateForEncryption(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate")
	})

	t.Run("Certificate With Nil X509", func(t *testing.T) {
		cert := &cert.Certificate{
			Certificate: nil,
		}
		err := validateCertificateForEncryption(cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate")
	})
}

func TestValidateCertificateForDecryption(t *testing.T) {
	t.Run("Valid Certificate", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		assert.NoError(t, err)

		testCert := createTestCertificate(t, rsaKeys)
		err = validateCertificateForDecryption(testCert)
		assert.NoError(t, err)
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		err := validateCertificateForDecryption(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate")
	})
}
