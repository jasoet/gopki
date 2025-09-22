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

func TestCreateEd25519PKCS7Signature(t *testing.T) {
	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Test Certificate",
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

	testData := []byte("Hello, Ed25519 PKCS#7 World!")

	t.Run("Attached Signature", func(t *testing.T) {
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, false)
		if err != nil {
			t.Fatalf("Failed to create attached PKCS#7 signature: %v", err)
		}

		if len(pkcs7Data) == 0 {
			t.Fatal("PKCS#7 signature data is empty")
		}

		t.Logf("Attached PKCS#7 signature created: %d bytes", len(pkcs7Data))

		// Verify the signature
		info, err := VerifyEd25519PKCS7Signature(testData, pkcs7Data)
		if err != nil {
			t.Fatalf("Failed to verify attached signature: %v", err)
		}

		if !info.Verified {
			t.Fatal("Signature verification failed")
		}

		if info.Certificate.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Error("Certificate serial number mismatch")
		}

		t.Logf("Attached PKCS#7 signature verified successfully")
	})

	t.Run("Detached Signature", func(t *testing.T) {
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create detached PKCS#7 signature: %v", err)
		}

		if len(pkcs7Data) == 0 {
			t.Fatal("PKCS#7 signature data is empty")
		}

		t.Logf("Detached PKCS#7 signature created: %d bytes", len(pkcs7Data))

		// Verify the signature
		info, err := VerifyEd25519PKCS7Signature(testData, pkcs7Data)
		if err != nil {
			t.Fatalf("Failed to verify detached signature: %v", err)
		}

		if !info.Verified {
			t.Fatal("Signature verification failed")
		}

		t.Logf("Detached PKCS#7 signature verified successfully")
	})

	t.Run("Large Data", func(t *testing.T) {
		// Test with larger data
		largeData := make([]byte, 10240) // 10KB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		pkcs7Data, err := CreateEd25519PKCS7Signature(largeData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create PKCS#7 signature for large data: %v", err)
		}

		info, err := VerifyEd25519PKCS7Signature(largeData, pkcs7Data)
		if err != nil {
			t.Fatalf("Failed to verify large data signature: %v", err)
		}

		if !info.Verified {
			t.Fatal("Large data signature verification failed")
		}

		t.Logf("Large data PKCS#7 signature verified successfully")
	})
}

func TestVerifyEd25519PKCS7Signature(t *testing.T) {
	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Ed25519 Verify Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

	testData := []byte("Verification test data")

	t.Run("Valid Signature", func(t *testing.T) {
		// Create signature
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create signature: %v", err)
		}

		// Verify signature
		info, err := VerifyEd25519PKCS7Signature(testData, pkcs7Data)
		if err != nil {
			t.Fatalf("Verification failed: %v", err)
		}

		if !info.Verified {
			t.Fatal("Signature should be valid")
		}

		if info.Certificate == nil {
			t.Fatal("Certificate should be present")
		}

		if len(info.Signature) != ed25519.SignatureSize {
			t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(info.Signature))
		}

		t.Logf("Valid signature verified successfully")
	})

	t.Run("Tampered Data", func(t *testing.T) {
		// Create signature
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create signature: %v", err)
		}

		// Tamper with the data
		tamperedData := append([]byte(nil), testData...)
		tamperedData[0] ^= 0x01

		// Verify should fail
		_, err = VerifyEd25519PKCS7Signature(tamperedData, pkcs7Data)
		if err == nil {
			t.Fatal("Should have failed with tampered data")
		}

		t.Logf("Correctly detected tampered data: %v", err)
	})
}

func TestIsEd25519PKCS7(t *testing.T) {
	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Ed25519 Detection Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

	testData := []byte("Detection test data")

	t.Run("Ed25519 PKCS#7", func(t *testing.T) {
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create signature: %v", err)
		}

		isEd25519, err := IsEd25519PKCS7(pkcs7Data)
		if err != nil {
			t.Fatalf("Detection failed: %v", err)
		}

		if !isEd25519 {
			t.Fatal("Should detect Ed25519 PKCS#7 format")
		}

		t.Logf("Ed25519 PKCS#7 detected correctly")
	})

	t.Run("Non-PKCS#7 Data", func(t *testing.T) {
		nonPKCS7Data := []byte("This is not PKCS#7 data")

		isEd25519, err := IsEd25519PKCS7(nonPKCS7Data)
		if err == nil {
			t.Fatal("Should fail for non-PKCS#7 data")
		}

		if isEd25519 {
			t.Fatal("Should not detect Ed25519 in non-PKCS#7 data")
		}

		t.Logf("Correctly rejected non-PKCS#7 data")
	})
}

func TestValidateEd25519PKCS7Structure(t *testing.T) {
	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName: "Ed25519 Validation Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

	testData := []byte("Structure validation test")

	t.Run("Valid Structure", func(t *testing.T) {
		pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			t.Fatalf("Failed to create signature: %v", err)
		}

		err = ValidateEd25519PKCS7Structure(pkcs7Data)
		if err != nil {
			t.Fatalf("Structure validation failed: %v", err)
		}

		t.Logf("Structure validation passed")
	})

	t.Run("Invalid Data", func(t *testing.T) {
		invalidData := []byte("Invalid PKCS#7 structure")

		err := ValidateEd25519PKCS7Structure(invalidData)
		if err == nil {
			t.Fatal("Should fail for invalid structure")
		}

		t.Logf("Correctly rejected invalid structure: %v", err)
	})
}

func TestEd25519PKCS7ErrorHandling(t *testing.T) {
	t.Run("Invalid Private Key Size", func(t *testing.T) {
		invalidKey := make([]byte, 10) // Wrong size
		cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
		data := []byte("test")

		_, err := CreateEd25519PKCS7Signature(data, invalidKey, cert, true)
		if err == nil {
			t.Fatal("Should fail for invalid private key size")
		}

		t.Logf("Correctly rejected invalid key size: %v", err)
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		data := []byte("test")

		_, err = CreateEd25519PKCS7Signature(data, privateKey, nil, true)
		if err == nil {
			t.Fatal("Should fail for nil certificate")
		}

		t.Logf("Correctly rejected nil certificate: %v", err)
	})

	t.Run("Invalid PKCS#7 Data", func(t *testing.T) {
		invalidData := []byte("Invalid PKCS#7 data")
		testData := []byte("test")

		_, err := VerifyEd25519PKCS7Signature(testData, invalidData)
		if err == nil {
			t.Fatal("Should fail for invalid PKCS#7 data")
		}

		t.Logf("Correctly rejected invalid PKCS#7 data: %v", err)
	})
}

// Benchmark the Ed25519 PKCS#7 operations
func BenchmarkEd25519PKCS7Creation(b *testing.B) {
	// Setup
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Benchmark Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		b.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		b.Fatalf("Failed to parse certificate: %v", err)
	}

	testData := []byte("Benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
		if err != nil {
			b.Fatalf("Signature creation failed: %v", err)
		}
	}
}

func BenchmarkEd25519PKCS7Verification(b *testing.B) {
	// Setup
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Benchmark Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		b.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		b.Fatalf("Failed to parse certificate: %v", err)
	}

	testData := []byte("Benchmark test data")
	pkcs7Data, err := CreateEd25519PKCS7Signature(testData, privateKey, cert, true)
	if err != nil {
		b.Fatalf("Failed to create signature: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyEd25519PKCS7Signature(testData, pkcs7Data)
		if err != nil {
			b.Fatalf("Signature verification failed: %v", err)
		}
	}
}
