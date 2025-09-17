package encryption

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair/algo"
)

func TestNewCMSImplementation(t *testing.T) {
	// Generate RSA key pair
	rsaKeys, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Create test certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, rsaKeys.PublicKey, rsaKeys.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	testData := []byte("test data for new CMS implementation")

	// Create EncryptedData with recipient
	encData := &EncryptedData{
		Algorithm: AlgorithmEnvelope,
		Format:    FormatCMS,
		Data:      testData,
		Recipients: []*RecipientInfo{
			{
				Certificate:            cert,
				KeyEncryptionAlgorithm: AlgorithmRSAOAEP,
			},
		},
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}

	t.Run("EncodeToCMS", func(t *testing.T) {
		encoded, err := EncodeToCMS(encData)
		if err != nil {
			t.Fatalf("Failed to encode to CMS: %v", err)
		}

		if len(encoded) == 0 {
			t.Error("Encoded CMS data is empty")
		}
	})

	t.Run("ValidateCMS", func(t *testing.T) {
		encoded, err := EncodeToCMS(encData)
		if err != nil {
			t.Fatalf("Failed to encode to CMS: %v", err)
		}

		err = ValidateCMS(encoded)
		if err != nil {
			t.Errorf("CMS validation failed: %v", err)
		}
	})

	t.Run("DecodeFromCMS", func(t *testing.T) {
		encoded, err := EncodeToCMS(encData)
		if err != nil {
			t.Fatalf("Failed to encode to CMS: %v", err)
		}

		decoded, err := DecodeFromCMS(encoded, cert, rsaKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to decode from CMS: %v", err)
		}

		if string(decoded.Data) != string(testData) {
			t.Errorf("Decoded data doesn't match. Expected: %s, Got: %s", string(testData), string(decoded.Data))
		}
	})

	t.Run("DecodeDataWithKey", func(t *testing.T) {
		encoded, err := EncodeData(encData)
		if err != nil {
			t.Fatalf("Failed to encode data: %v", err)
		}

		decoded, err := DecodeDataWithKey(encoded, cert, rsaKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to decode with key: %v", err)
		}

		if string(decoded.Data) != string(testData) {
			t.Errorf("Decoded data doesn't match. Expected: %s, Got: %s", string(testData), string(decoded.Data))
		}
	})
}
