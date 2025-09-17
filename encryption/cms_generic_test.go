package encryption

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair/algo"
)

// TestGenericPrivateKeyTypes demonstrates type safety with different private key types
func TestGenericPrivateKeyTypes(t *testing.T) {
	testData := []byte("generic test data")

	t.Run("RSAPrivateKey", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		// Create certificate
		cert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)

		// Create encrypted data
		encData := createTestEncryptedData(testData, cert)

		// Encode
		encoded, err := EncodeToCMS(encData)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		// Decode with RSA private key (type inferred as *rsa.PrivateKey)
		decoded, err := DecodeFromCMS(encoded, cert, rsaKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to decode with RSA private key: %v", err)
		}

		if string(decoded.Data) != string(testData) {
			t.Errorf("Data mismatch")
		}

		// Also test with explicit type parameter
		decoded2, err := DecodeFromCMS[*rsa.PrivateKey](encoded, cert, rsaKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to decode with explicit RSA type: %v", err)
		}

		if string(decoded2.Data) != string(testData) {
			t.Errorf("Data mismatch with explicit type")
		}
	})

	t.Run("TypeSafetyDemo", func(t *testing.T) {
		// Demonstrate that the generic function accepts different private key types
		// Note: We only test with RSA for actual encryption since PKCS7 library
		// primarily supports RSA for envelope encryption

		// Generate RSA key pair for actual testing
		rsaKeys, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		cert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)
		encData := createTestEncryptedData(testData, cert)
		encoded, err := EncodeToCMS(encData)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		// Demonstrate type safety with different ways to call the generic function
		t.Run("TypeInference", func(t *testing.T) {
			// Type inferred automatically
			decoded, err := DecodeFromCMS(encoded, cert, rsaKeys.PrivateKey)
			if err != nil {
				t.Fatalf("Failed with type inference: %v", err)
			}
			if string(decoded.Data) != string(testData) {
				t.Error("Data mismatch")
			}
		})

		t.Run("ExplicitType", func(t *testing.T) {
			// Explicit type parameter
			decoded, err := DecodeFromCMS[*rsa.PrivateKey](encoded, cert, rsaKeys.PrivateKey)
			if err != nil {
				t.Fatalf("Failed with explicit type: %v", err)
			}
			if string(decoded.Data) != string(testData) {
				t.Error("Data mismatch")
			}
		})

		t.Run("TypeCompatibility", func(t *testing.T) {
			// Generate other key types just to show they compile
			ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
			}

			// These demonstrate type safety - they compile with different key types
			dummyData := []byte("dummy")
			dummyCert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)

			// These would compile but may fail at runtime due to PKCS7 limitations
			_, _ = DecodeFromCMS(dummyData, dummyCert, rsaKeys.PrivateKey)   // *rsa.PrivateKey
			_, _ = DecodeFromCMS(dummyData, dummyCert, ecdsaKeys.PrivateKey) // *ecdsa.PrivateKey
			_, _ = DecodeFromCMS(dummyData, dummyCert, ed25519Priv)          // ed25519.PrivateKey

			t.Log("Generic function accepts multiple private key types at compile time")
		})
	})
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, publicKey interface{}, privateKey interface{}) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Generic Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Helper function to create test encrypted data
func createTestEncryptedData(data []byte, cert *x509.Certificate) *EncryptedData {
	return &EncryptedData{
		Algorithm: AlgorithmEnvelope,
		Format:    FormatCMS,
		Data:      data,
		Recipients: []*RecipientInfo{
			{
				Certificate:            cert,
				KeyEncryptionAlgorithm: AlgorithmRSAOAEP,
			},
		},
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}
}
