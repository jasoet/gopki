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

func TestSimpleEd25519PKCS7(t *testing.T) {
	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Simple Test Certificate",
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

	testData := []byte("Hello, Simple Ed25519 PKCS#7 World!")

	t.Run("Simple Format Creation and Verification", func(t *testing.T) {
		// Create simple PKCS#7 signature
		pkcs7Data, err := SimpleEd25519PKCS7(testData, privateKey, cert)
		if err != nil {
			t.Fatalf("Failed to create simple PKCS#7 signature: %v", err)
		}

		if len(pkcs7Data) == 0 {
			t.Fatal("PKCS#7 signature data is empty")
		}

		t.Logf("Simple PKCS#7 signature created: %d bytes", len(pkcs7Data))

		// Verify the signature
		info, err := VerifySimpleEd25519PKCS7(testData, pkcs7Data)
		if err != nil {
			t.Fatalf("Failed to verify simple signature: %v", err)
		}

		if !info.Verified {
			t.Fatal("Signature verification failed")
		}

		if info.Certificate.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Error("Certificate serial number mismatch")
		}

		t.Logf("Simple PKCS#7 signature verified successfully")
	})

	t.Run("Format Detection", func(t *testing.T) {
		// Create simple PKCS#7 signature
		pkcs7Data, err := SimpleEd25519PKCS7(testData, privateKey, cert)
		if err != nil {
			t.Fatalf("Failed to create simple PKCS#7 signature: %v", err)
		}

		// Test format detection
		if !IsSimpleEd25519PKCS7(pkcs7Data) {
			t.Fatal("Failed to detect simple Ed25519 PKCS#7 format")
		}

		// Test with non-simple data
		nonSimpleData := []byte("not a simple Ed25519 PKCS#7 signature")
		if IsSimpleEd25519PKCS7(nonSimpleData) {
			t.Fatal("Incorrectly detected simple format in non-simple data")
		}

		t.Logf("Format detection working correctly")
	})

	t.Run("Tampered Data Detection", func(t *testing.T) {
		// Create simple PKCS#7 signature
		pkcs7Data, err := SimpleEd25519PKCS7(testData, privateKey, cert)
		if err != nil {
			t.Fatalf("Failed to create simple PKCS#7 signature: %v", err)
		}

		// Tamper with the data
		tamperedData := append([]byte(nil), testData...)
		tamperedData[0] ^= 0x01

		// Try to verify with tampered data
		_, err = VerifySimpleEd25519PKCS7(tamperedData, pkcs7Data)
		if err == nil {
			t.Fatal("Should have failed with tampered data")
		}

		t.Logf("Correctly detected tampered data: %v", err)
	})

	t.Run("Large Data", func(t *testing.T) {
		// Test with larger data
		largeData := make([]byte, 10240) // 10KB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		pkcs7Data, err := SimpleEd25519PKCS7(largeData, privateKey, cert)
		if err != nil {
			t.Fatalf("Failed to create PKCS#7 signature for large data: %v", err)
		}

		info, err := VerifySimpleEd25519PKCS7(largeData, pkcs7Data)
		if err != nil {
			t.Fatalf("Failed to verify large data signature: %v", err)
		}

		if !info.Verified {
			t.Fatal("Large data signature verification failed")
		}

		t.Logf("Large data PKCS#7 signature verified successfully")
	})
}

func TestSimpleEd25519PKCS7ErrorHandling(t *testing.T) {
	t.Run("Invalid Private Key Size", func(t *testing.T) {
		invalidKey := make([]byte, 10) // Wrong size
		cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
		data := []byte("test")

		_, err := SimpleEd25519PKCS7(data, invalidKey, cert)
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

		_, err = SimpleEd25519PKCS7(data, privateKey, nil)
		if err == nil {
			t.Fatal("Should fail for nil certificate")
		}

		t.Logf("Correctly rejected nil certificate: %v", err)
	})

	t.Run("Invalid PKCS#7 Data", func(t *testing.T) {
		invalidData := []byte("Invalid PKCS#7 data")
		testData := []byte("test")

		_, err := VerifySimpleEd25519PKCS7(testData, invalidData)
		if err == nil {
			t.Fatal("Should fail for invalid PKCS#7 data")
		}

		t.Logf("Correctly rejected invalid PKCS#7 data: %v", err)
	})
}

// Benchmark the simple Ed25519 PKCS#7 operations
func BenchmarkSimpleEd25519PKCS7Creation(b *testing.B) {
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
		_, err := SimpleEd25519PKCS7(testData, privateKey, cert)
		if err != nil {
			b.Fatalf("Signature creation failed: %v", err)
		}
	}
}

func BenchmarkSimpleEd25519PKCS7Verification(b *testing.B) {
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
	pkcs7Data, err := SimpleEd25519PKCS7(testData, privateKey, cert)
	if err != nil {
		b.Fatalf("Failed to create signature: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifySimpleEd25519PKCS7(testData, pkcs7Data)
		if err != nil {
			b.Fatalf("Signature verification failed: %v", err)
		}
	}
}
