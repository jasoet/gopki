package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestDebugEd25519PKCS7(t *testing.T) {
	t.Logf("🧪 Testing Ed25519 PKCS#7 with detailed debugging")

	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Debug Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	testData := []byte("Hello, Ed25519 PKCS#7 Debug World!")
	t.Logf("Test data: %s", testData)

	t.Run("Debug Creation and Verification", func(t *testing.T) {
		t.Logf("=== CREATION PHASE ===")
		pkcs7Data, err := DebugCreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create debug PKCS#7 signature: %v", err)
		}

		t.Logf("=== VERIFICATION PHASE ===")
		info, err := DebugVerifyEd25519PKCS7Signature(testData, pkcs7Data)
		if err != nil {
			t.Fatalf("Failed to verify debug signature: %v", err)
		}

		if !info.Verified {
			t.Fatal("Signature verification failed")
		}

		t.Logf("✅ Debug test successful!")
	})

	t.Run("Compare with Original Implementation", func(t *testing.T) {
		t.Logf("=== TESTING ORIGINAL IMPLEMENTATION ===")

		// Try the original implementation
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Logf("❌ Original implementation failed as expected: %v", err)
			return
		}

		// If it succeeds, try to verify
		info, err := VerifyEd25519PKCS7Signature(testData, pkcs7Data)
		if err != nil {
			t.Logf("❌ Original verification failed: %v", err)
			return
		}

		if info.Verified {
			t.Logf("✅ Original implementation works!")
		}
	})
}
