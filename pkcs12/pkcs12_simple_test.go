package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSimpleP12Operations(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("Basic Create and Load", func(t *testing.T) {
		// Generate RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Create self-signed certificate
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test Certificate",
				Organization: []string{"Test Org"},
				Country:      []string{"US"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Create P12 file
		p12File := filepath.Join(tempDir, "test.p12")
		password := "test123"
		opts := DefaultCreateOptions(password)

		err = CreateP12File(p12File, privateKey, certificate, nil, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(p12File); os.IsNotExist(err) {
			t.Fatalf("P12 file was not created")
		}

		// Load P12 file
		loadOpts := DefaultLoadOptions(password)
		container, err := LoadFromP12File(p12File, loadOpts)
		if err != nil {
			t.Fatalf("Failed to load P12 file: %v", err)
		}

		// Validate container
		if err := container.Validate(); err != nil {
			t.Errorf("Container validation failed: %v", err)
		}

		// Check key type
		if container.GetKeyType() != "RSA" {
			t.Errorf("Expected RSA key type, got %s", container.GetKeyType())
		}

		// Check certificate subject
		if container.Certificate.Subject.CommonName != "Test Certificate" {
			t.Errorf("Certificate subject mismatch")
		}
	})

	t.Run("Generate Test P12", func(t *testing.T) {
		p12File := filepath.Join(tempDir, "generated.p12")
		password := "generated123"

		err := GenerateTestP12(p12File, password)
		if err != nil {
			t.Fatalf("Failed to generate test P12: %v", err)
		}

		// Verify the generated file can be loaded
		loadOpts := DefaultLoadOptions(password)
		container, err := LoadFromP12File(p12File, loadOpts)
		if err != nil {
			t.Fatalf("Failed to load generated test P12: %v", err)
		}

		if container.Certificate.Subject.CommonName != "Test Certificate" {
			t.Errorf("Generated test certificate has wrong subject")
		}
	})

	t.Run("Quick Functions", func(t *testing.T) {
		// Generate key and certificate
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "Quick Test",
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			SerialNumber: big.NewInt(2),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Quick create
		p12File := filepath.Join(tempDir, "quick.p12")
		password := "quick123"

		err = QuickCreateP12(p12File, password, privateKey, certificate)
		if err != nil {
			t.Fatalf("QuickCreateP12 failed: %v", err)
		}

		// Quick load
		container, err := QuickLoadP12(p12File, password)
		if err != nil {
			t.Fatalf("QuickLoadP12 failed: %v", err)
		}

		if container.Certificate.Subject.CommonName != "Quick Test" {
			t.Errorf("Quick load certificate subject mismatch")
		}
	})
}

func TestP12ErrorHandling(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("Invalid Password", func(t *testing.T) {
		// Create a P12 file first
		err := GenerateTestP12(filepath.Join(tempDir, "test.p12"), "correct_password")
		if err != nil {
			t.Fatalf("Failed to generate test P12: %v", err)
		}

		// Try to load with wrong password
		loadOpts := DefaultLoadOptions("wrong_password")
		_, err = LoadFromP12File(filepath.Join(tempDir, "test.p12"), loadOpts)
		if err == nil {
			t.Error("Expected error with wrong password")
		}
	})

	t.Run("Missing File", func(t *testing.T) {
		loadOpts := DefaultLoadOptions("password")
		_, err := LoadFromP12File("nonexistent.p12", loadOpts)
		if err == nil {
			t.Error("Expected error for missing file")
		}
	})

	t.Run("Nil Parameters", func(t *testing.T) {
		opts := DefaultCreateOptions("password")

		// Test nil private key
		_, err := CreateP12(nil, &x509.Certificate{}, nil, opts)
		if err == nil {
			t.Error("Expected error for nil private key")
		}

		// Test nil certificate
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err = CreateP12(privateKey, nil, nil, opts)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
	})
}

func TestP12CertificateInfo(t *testing.T) {
	tempDir := t.TempDir()

	// Create test P12
	p12File := filepath.Join(tempDir, "info_test.p12")
	err := GenerateTestP12(p12File, "test123")
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}

	// Load and get info
	container, err := QuickLoadP12(p12File, "test123")
	if err != nil {
		t.Fatalf("Failed to load P12: %v", err)
	}

	info := GetCertificateInfo(container.Certificate)
	if info == nil {
		t.Fatal("Certificate info is nil")
	}

	// Check some expected fields
	if subject, ok := info["subject"].(string); !ok || subject == "" {
		t.Error("Subject field missing or empty")
	}

	if keyUsage, ok := info["key_usage"].([]string); !ok || len(keyUsage) == 0 {
		t.Error("Key usage field missing or empty")
	}
}