package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/jasoet/gopki/keypair/algo"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateSelfSignedCertificate(t *testing.T) {
	t.Run("RSA self-signed certificate", func(t *testing.T) {
		keyPair, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		request := CertificateRequest{
			Subject: pkix.Name{
				Country:      []string{"US"},
				Organization: []string{"Test Organization"},
				CommonName:   "test.example.com",
			},
			DNSNames:  []string{"test.example.com", "www.test.example.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 24 * time.Hour,
		}

		cert, err := CreateSelfSignedCertificate(keyPair, request)
		if err != nil {
			t.Fatalf("Failed to create self-signed certificate: %v", err)
		}

		if cert.Certificate == nil {
			t.Fatal("Certificate is nil")
		}

		if len(cert.PEMData) == 0 {
			t.Fatal("PEM data is empty")
		}

		if cert.Certificate.Subject.CommonName != "test.example.com" {
			t.Fatalf("Expected CommonName 'test.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}

		if len(cert.Certificate.DNSNames) != 2 {
			t.Fatalf("Expected 2 DNS names, got %d", len(cert.Certificate.DNSNames))
		}
	})

	t.Run("ECDSA self-signed certificate", func(t *testing.T) {
		keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		request := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "ecdsa.example.com",
			},
			ValidFor: 30 * 24 * time.Hour,
		}

		cert, err := CreateSelfSignedCertificate(keyPair, request)
		if err != nil {
			t.Fatalf("Failed to create ECDSA self-signed certificate: %v", err)
		}

		if cert.Certificate.Subject.CommonName != "ecdsa.example.com" {
			t.Fatalf("Expected CommonName 'ecdsa.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}
	})

	t.Run("Ed25519 self-signed certificate", func(t *testing.T) {
		keyPair, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		request := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "ed25519.example.com",
			},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
			ValidFor:    24 * time.Hour,
		}

		cert, err := CreateSelfSignedCertificate(keyPair, request)
		if err != nil {
			t.Fatalf("Failed to create Ed25519 self-signed certificate: %v", err)
		}

		if len(cert.Certificate.IPAddresses) != 1 {
			t.Fatalf("Expected 1 IP address, got %d", len(cert.Certificate.IPAddresses))
		}
	})
}

func TestCreateCACertificate(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	request := CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test CA"},
			CommonName:   "Test Root CA",
		},
		ValidFor: 10 * 365 * 24 * time.Hour,
	}

	caCert, err := CreateCACertificate(keyPair, request)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	if !caCert.Certificate.IsCA {
		t.Fatal("Certificate is not marked as CA")
	}

	if caCert.Certificate.Subject.CommonName != "Test Root CA" {
		t.Fatalf("Expected CommonName 'Test Root CA', got '%s'", caCert.Certificate.Subject.CommonName)
	}

	expectedKeyUsage := caCert.Certificate.KeyUsage
	if expectedKeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA certificate missing CertSign key usage")
	}

	if expectedKeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("CA certificate missing CRLSign key usage")
	}
}

func TestSignCertificate(t *testing.T) {
	// Create CA
	caKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key pair: %v", err)
	}

	caRequest := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		ValidFor: 10 * 365 * 24 * time.Hour,
	}

	caCert, err := CreateCACertificate(caKeyPair, caRequest)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Create server key pair
	serverKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	serverRequest := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "server.example.com",
		},
		DNSNames:     []string{"server.example.com", "api.example.com"},
		EmailAddress: []string{"admin@example.com"},
		ValidFor:     365 * 24 * time.Hour,
	}

	// Sign server certificate
	serverCert, err := SignCertificate(caCert, caKeyPair, serverRequest, serverKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to sign server certificate: %v", err)
	}

	if serverCert.Certificate.Subject.CommonName != "server.example.com" {
		t.Fatalf("Expected CommonName 'server.example.com', got '%s'", serverCert.Certificate.Subject.CommonName)
	}

	if serverCert.Certificate.IsCA {
		t.Fatal("Server certificate should not be marked as CA")
	}

	if len(serverCert.Certificate.DNSNames) != 2 {
		t.Fatalf("Expected 2 DNS names, got %d", len(serverCert.Certificate.DNSNames))
	}

	if len(serverCert.Certificate.EmailAddresses) != 1 {
		t.Fatalf("Expected 1 email address, got %d", len(serverCert.Certificate.EmailAddresses))
	}
}

func TestVerifyCertificate(t *testing.T) {
	// Create CA
	caKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key pair: %v", err)
	}

	caRequest := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		ValidFor: 10 * 365 * 24 * time.Hour,
	}

	caCert, err := CreateCACertificate(caKeyPair, caRequest)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Create and sign a certificate
	serverKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	serverRequest := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "server.example.com",
		},
		ValidFor: 365 * 24 * time.Hour,
	}

	serverCert, err := SignCertificate(caCert, caKeyPair, serverRequest, serverKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to sign server certificate: %v", err)
	}

	// Verify the certificate
	err = VerifyCertificate(serverCert, caCert)
	if err != nil {
		t.Fatalf("Certificate verification failed: %v", err)
	}

	// Test verification with wrong CA
	wrongCaKeyPair, _ := algo.GenerateRSAKeyPair(2048)
	wrongCaRequest := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Wrong CA",
		},
		ValidFor: 10 * 365 * 24 * time.Hour,
	}

	wrongCaCert, err := CreateCACertificate(wrongCaKeyPair, wrongCaRequest)
	if err != nil {
		t.Fatalf("Failed to create wrong CA certificate: %v", err)
	}

	err = VerifyCertificate(serverCert, wrongCaCert)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong CA")
	}
}

func TestCertificateFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "test.pem")

	keyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	request := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "file-test.example.com",
		},
		ValidFor: 365 * 24 * time.Hour,
	}

	cert, err := CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Save certificate to file
	err = cert.SaveToFile(certFile)
	if err != nil {
		t.Fatalf("Failed to save certificate to file: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Fatal("Certificate file was not created")
	}

	// Load certificate from file
	loadedCert, err := LoadCertificateFromFile(certFile)
	if err != nil {
		t.Fatalf("Failed to load certificate from file: %v", err)
	}

	if loadedCert.Certificate.Subject.CommonName != cert.Certificate.Subject.CommonName {
		t.Fatal("Loaded certificate doesn't match original")
	}

	if string(loadedCert.PEMData) != string(cert.PEMData) {
		t.Fatal("Loaded PEM data doesn't match original")
	}
}

func TestParseCertificateFromPEM(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	request := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "parse-test.example.com",
		},
		ValidFor: 365 * 24 * time.Hour,
	}

	originalCert, err := CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse from PEM data
	parsedCert, err := ParseCertificateFromPEM(originalCert.PEMData)
	if err != nil {
		t.Fatalf("Failed to parse certificate from PEM: %v", err)
	}

	if parsedCert.Certificate.Subject.CommonName != originalCert.Certificate.Subject.CommonName {
		t.Fatal("Parsed certificate doesn't match original")
	}

	// Test with invalid PEM data
	invalidPEM := []byte("invalid pem data")
	_, err = ParseCertificateFromPEM(invalidPEM)
	if err == nil {
		t.Fatal("Expected error when parsing invalid PEM data")
	}

	// Test with wrong PEM type
	wrongTypePEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7
-----END PRIVATE KEY-----`)
	_, err = ParseCertificateFromPEM(wrongTypePEM)
	if err == nil {
		t.Fatal("Expected error when parsing wrong PEM type")
	}
}

func TestCertificateDefaultValues(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test with minimal request (should use defaults)
	request := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "default-test.example.com",
		},
	}

	cert, err := CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		t.Fatalf("Failed to create certificate with defaults: %v", err)
	}

	// Check that ValidFrom was set to current time (within 1 minute)
	timeDiff := time.Now().Sub(cert.Certificate.NotBefore)
	if timeDiff > time.Minute || timeDiff < 0 {
		t.Fatal("ValidFrom was not set to current time")
	}

	// Check that ValidFor was set to 1 year (default)
	expectedValidFor := 365 * 24 * time.Hour
	actualValidFor := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)

	// Allow some tolerance for time differences
	tolerance := time.Minute
	if actualValidFor > expectedValidFor+tolerance || actualValidFor < expectedValidFor-tolerance {
		t.Fatalf("Expected ValidFor ~%v, got %v", expectedValidFor, actualValidFor)
	}
}

// TestUnsupportedKeyPairType is no longer needed because the generic constraint
// [T keypair.KeyPair] ensures type safety at compile time. Invalid types cannot
// be passed to CreateSelfSignedCertificate or CreateCACertificate anymore.
//
// The previous test tried to pass a string which is now a compile-time error:
// string does not satisfy keypair.KeyPair constraint
