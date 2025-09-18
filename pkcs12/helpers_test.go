package pkcs12

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// TestValidateKeyPairMatch tests the validateKeyPairMatch function with various key types and scenarios
func TestValidateKeyPairMatch(t *testing.T) {
	// Generate RSA key pair
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaKeyPair := rsaManager.KeyPair()

	// Generate ECDSA key pair
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	ecdsaKeyPair := ecdsaManager.KeyPair()

	// Generate Ed25519 key pair
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	ed25519KeyPair := ed25519Manager.KeyPair()

	// Generate a different RSA key pair for mismatch testing
	differentRSAManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate different RSA key pair: %v", err)
	}
	differentRSAKeyPair := differentRSAManager.KeyPair()

	t.Run("ValidRSAKeyPairMatch", func(t *testing.T) {
		err := validateKeyPairMatch(rsaKeyPair.PrivateKey, rsaKeyPair.PublicKey)
		if err != nil {
			t.Errorf("Expected RSA key pair to match, got error: %v", err)
		}
	})

	t.Run("ValidECDSAKeyPairMatch", func(t *testing.T) {
		err := validateKeyPairMatch(ecdsaKeyPair.PrivateKey, ecdsaKeyPair.PublicKey)
		if err != nil {
			t.Errorf("Expected ECDSA key pair to match, got error: %v", err)
		}
	})

	t.Run("ValidEd25519KeyPairMatch", func(t *testing.T) {
		err := validateKeyPairMatch(ed25519KeyPair.PrivateKey, ed25519KeyPair.PublicKey)
		if err != nil {
			t.Errorf("Expected Ed25519 key pair to match, got error: %v", err)
		}
	})

	t.Run("RSAKeyPairMismatch", func(t *testing.T) {
		err := validateKeyPairMatch(rsaKeyPair.PrivateKey, differentRSAKeyPair.PublicKey)
		if err == nil {
			t.Error("Expected RSA key pair mismatch to produce an error")
		}
	})

	t.Run("RSAPrivateKeyWithECDSAPublicKey", func(t *testing.T) {
		err := validateKeyPairMatch(rsaKeyPair.PrivateKey, ecdsaKeyPair.PublicKey)
		if err == nil {
			t.Error("Expected RSA private key with ECDSA public key to produce an error")
		}
		if err != nil && err.Error() != "private key is RSA but public key is not" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})

	t.Run("ECDSAPrivateKeyWithRSAPublicKey", func(t *testing.T) {
		err := validateKeyPairMatch(ecdsaKeyPair.PrivateKey, rsaKeyPair.PublicKey)
		if err == nil {
			t.Error("Expected ECDSA private key with RSA public key to produce an error")
		}
		if err != nil && err.Error() != "private key is ECDSA but public key is not" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})

	t.Run("Ed25519PrivateKeyWithRSAPublicKey", func(t *testing.T) {
		err := validateKeyPairMatch(ed25519KeyPair.PrivateKey, rsaKeyPair.PublicKey)
		if err == nil {
			t.Error("Expected Ed25519 private key with RSA public key to produce an error")
		}
		if err != nil && err.Error() != "private key is Ed25519 but public key is not" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})

	t.Run("UnsupportedPrivateKeyType", func(t *testing.T) {
		// Create an unsupported private key type (using a string as a mock)
		unsupportedKey := "not a real key"
		err := validateKeyPairMatch(unsupportedKey, rsaKeyPair.PublicKey)
		if err == nil {
			t.Error("Expected unsupported private key type to produce an error")
		}
		if err != nil && !contains(err.Error(), "unsupported private key type") {
			t.Errorf("Expected unsupported key type error, got: %v", err)
		}
	})

	t.Run("ECDSAKeyPairMismatch", func(t *testing.T) {
		// Generate another ECDSA key pair for mismatch testing
		differentECDSAManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate different ECDSA key pair: %v", err)
		}
		differentECDSAKeyPair := differentECDSAManager.KeyPair()

		err = validateKeyPairMatch(ecdsaKeyPair.PrivateKey, differentECDSAKeyPair.PublicKey)
		if err == nil {
			t.Error("Expected ECDSA key pair mismatch to produce an error")
		}
		if err != nil && err.Error() != "ECDSA private key does not match public key" {
			t.Errorf("Expected specific ECDSA mismatch error, got: %v", err)
		}
	})

	t.Run("Ed25519KeyPairMismatch", func(t *testing.T) {
		// Generate another Ed25519 key pair for mismatch testing
		differentEd25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
		if err != nil {
			t.Fatalf("Failed to generate different Ed25519 key pair: %v", err)
		}
		differentEd25519KeyPair := differentEd25519Manager.KeyPair()

		err = validateKeyPairMatch(ed25519KeyPair.PrivateKey, differentEd25519KeyPair.PublicKey)
		if err == nil {
			t.Error("Expected Ed25519 key pair mismatch to produce an error")
		}
		if err != nil && err.Error() != "Ed25519 private key does not match public key" {
			t.Errorf("Expected specific Ed25519 mismatch error, got: %v", err)
		}
	})
}

// TestGetExtKeyUsageStrings tests the getExtKeyUsageStrings function comprehensively
func TestGetExtKeyUsageStrings(t *testing.T) {
	testCases := []struct {
		name     string
		usages   []x509.ExtKeyUsage
		expected []string
	}{
		{
			name:     "EmptyUsages",
			usages:   []x509.ExtKeyUsage{},
			expected: []string{},
		},
		{
			name:     "ServerAuth",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: []string{"Server Authentication"},
		},
		{
			name:     "ClientAuth",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			expected: []string{"Client Authentication"},
		},
		{
			name:     "CodeSigning",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			expected: []string{"Code Signing"},
		},
		{
			name:     "EmailProtection",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			expected: []string{"Email Protection"},
		},
		{
			name:     "TimeStamping",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			expected: []string{"Time Stamping"},
		},
		{
			name:     "OCSPSigning",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			expected: []string{"OCSP Signing"},
		},
		{
			name: "MultipleUsages",
			usages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
			},
			expected: []string{
				"Server Authentication",
				"Client Authentication",
				"Code Signing",
			},
		},
		{
			name: "AllStandardUsages",
			usages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
				x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageTimeStamping,
				x509.ExtKeyUsageOCSPSigning,
			},
			expected: []string{
				"Server Authentication",
				"Client Authentication",
				"Code Signing",
				"Email Protection",
				"Time Stamping",
				"OCSP Signing",
			},
		},
		{
			name:     "UnknownUsage",
			usages:   []x509.ExtKeyUsage{x509.ExtKeyUsage(999)}, // Unknown usage value
			expected: []string{"Unknown (999)"},
		},
		{
			name: "MixedKnownAndUnknownUsages",
			usages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsage(888), // Unknown
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsage(777), // Unknown
			},
			expected: []string{
				"Server Authentication",
				"Unknown (888)",
				"Client Authentication",
				"Unknown (777)",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getExtKeyUsageStrings(tc.usages)

			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d usage strings, got %d", len(tc.expected), len(result))
				return
			}

			for i, expected := range tc.expected {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected usage string at index %d to be '%s', got '%s'", i, expected, result[i])
				}
			}
		})
	}
}

// TestGetCertificateInfoExtKeyUsage tests GetCertificateInfo with focus on extended key usage
func TestGetCertificateInfoExtKeyUsage(t *testing.T) {
	// Create a certificate with various extended key usages
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaKeyPair := rsaManager.KeyPair()

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Cert with ExtKeyUsage",
			Organization: []string{"Test Org"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
		SerialNumber: big.NewInt(12345),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, rsaKeyPair.PublicKey, rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test GetCertificateInfo
	info := GetCertificateInfo(cert)
	if info == nil {
		t.Error("Expected certificate info to be non-nil")
		return
	}

	// Check extended key usage strings
	extKeyUsage, ok := info["ext_key_usage"].([]string)
	if !ok {
		t.Error("Expected ext_key_usage to be []string")
		return
	}

	expectedExtKeyUsages := []string{
		"Server Authentication",
		"Client Authentication",
		"Code Signing",
	}

	if len(extKeyUsage) != len(expectedExtKeyUsages) {
		t.Errorf("Expected %d extended key usages, got %d", len(expectedExtKeyUsages), len(extKeyUsage))
	}

	for i, expected := range expectedExtKeyUsages {
		if i < len(extKeyUsage) && extKeyUsage[i] != expected {
			t.Errorf("Expected extended key usage %d to be '%s', got '%s'", i, expected, extKeyUsage[i])
		}
	}

	t.Run("NilCertificate", func(t *testing.T) {
		info := GetCertificateInfo(nil)
		if info != nil {
			t.Error("Expected nil certificate to return nil info")
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
		 (s[:len(substr)] == substr ||
		  s[len(s)-len(substr):] == substr ||
		  findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}