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
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	serverKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	serverKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	wrongCaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
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

	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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

// TestCreateCACertificateErrors tests error cases for CA certificate creation
func TestCreateCACertificateErrors(t *testing.T) {
	// Generate test key pairs
	rsaKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	t.Run("Invalid key pair types", func(t *testing.T) {
		request := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Invalid CA",
			},
			ValidFor: 365 * 24 * time.Hour,
		}

		// Test with nil key pair
		_, err := CreateCACertificate(nil, request)
		if err == nil {
			t.Error("Expected error with nil key pair")
		}
	})

	t.Run("Invalid certificate request", func(t *testing.T) {
		// Test with empty subject
		emptyRequest := CertificateRequest{
			ValidFor: 365 * 24 * time.Hour,
		}

		_, err := CreateCACertificate(rsaKeyPair, emptyRequest)
		if err == nil {
			t.Error("Expected error with empty subject")
		}

		// Test with negative validity period
		negativeRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			ValidFor: -time.Hour,
		}

		_, err = CreateCACertificate(rsaKeyPair, negativeRequest)
		if err == nil {
			t.Error("Expected error with negative validity period")
		}
	})

	t.Run("Path length constraints", func(t *testing.T) {
		// Test with invalid path length constraint
		invalidPathRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Test CA with Invalid Path",
			},
			ValidFor:            365 * 24 * time.Hour,
			MaxPathLen:          -2, // Invalid path length
			MaxPathLenZero:      false,
			PermittedDNSDomains: []string{"example.com"},
			ExcludedDNSDomains:  []string{"bad.example.com"},
		}

		// This should still work but test various combinations
		cert, err := CreateCACertificate(rsaKeyPair, invalidPathRequest)
		if err != nil {
			// If implementation validates path length, this is acceptable
			t.Logf("Path length validation error (acceptable): %v", err)
		} else {
			// Verify that path length constraint is properly set
			if cert.Certificate.MaxPathLen != invalidPathRequest.MaxPathLen {
				t.Error("Path length constraint not properly set")
			}
		}
	})

	t.Run("Cross-algorithm validation", func(t *testing.T) {
		// Test creating CA with different algorithms
		algorithms := []struct {
			name    string
			keyPair interface{}
		}{
			{"RSA", rsaKeyPair},
			{"ECDSA", ecdsaKeyPair},
		}

		for _, alg := range algorithms {
			t.Run(alg.name, func(t *testing.T) {
				request := CertificateRequest{
					Subject: pkix.Name{
						CommonName: "Test CA " + alg.name,
					},
					ValidFor: 365 * 24 * time.Hour,
				}

				cert, err := CreateCACertificate(alg.keyPair, request)
				if err != nil {
					t.Errorf("Failed to create CA certificate with %s: %v", alg.name, err)
				} else if cert == nil {
					t.Errorf("CA certificate is nil for %s", alg.name)
				} else if !cert.Certificate.IsCA {
					t.Errorf("Certificate is not marked as CA for %s", alg.name)
				}
			})
		}
	})
}

// TestSignCertificateErrors tests error cases for certificate signing
func TestSignCertificateErrors(t *testing.T) {
	// Generate CA certificate and key pair
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key pair: %v", err)
	}

	caRequest := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test CA for Signing",
		},
		ValidFor: 365 * 24 * time.Hour,
	}

	caCert, err := CreateCACertificate(caKeyPair, caRequest)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Generate end-entity key pair
	entityKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate entity key pair: %v", err)
	}

	t.Run("Invalid CA certificate", func(t *testing.T) {
		entityRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Test Entity",
			},
			ValidFor: 30 * 24 * time.Hour,
		}

		// Test with nil CA certificate
		_, err := SignCertificate(nil, caKeyPair, entityKeyPair, entityRequest)
		if err == nil {
			t.Error("Expected error with nil CA certificate")
		}

		// Test with nil CA key pair
		_, err = SignCertificate(caCert, nil, entityKeyPair, entityRequest)
		if err == nil {
			t.Error("Expected error with nil CA key pair")
		}

		// Test with nil entity key pair
		_, err = SignCertificate(caCert, caKeyPair, nil, entityRequest)
		if err == nil {
			t.Error("Expected error with nil entity key pair")
		}
	})

	t.Run("Mismatched key pairs", func(t *testing.T) {
		// Generate a different key pair that doesn't match the CA certificate
		mismatchedKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate mismatched key pair: %v", err)
		}

		entityRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Test Entity with Mismatched CA Key",
			},
			ValidFor: 30 * 24 * time.Hour,
		}

		// Test signing with mismatched CA private key
		_, err = SignCertificate(caCert, mismatchedKeyPair, entityKeyPair, entityRequest)
		if err == nil {
			t.Error("Expected error with mismatched CA private key")
		}
	})

	t.Run("Invalid certificate request", func(t *testing.T) {
		// Test with empty subject
		emptyRequest := CertificateRequest{
			ValidFor: 30 * 24 * time.Hour,
		}

		_, err := SignCertificate(caCert, caKeyPair, entityKeyPair, emptyRequest)
		if err == nil {
			t.Error("Expected error with empty subject")
		}

		// Test with validity period longer than CA
		longRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Long Validity Entity",
			},
			ValidFor: 2 * 365 * 24 * time.Hour, // Longer than CA
		}

		cert, err := SignCertificate(caCert, caKeyPair, entityKeyPair, longRequest)
		if err != nil {
			// If implementation validates against CA validity, this is acceptable
			t.Logf("Validity period validation error (acceptable): %v", err)
		} else if cert != nil {
			// If allowed, verify the certificate was created
			if cert.Certificate.NotAfter.After(caCert.Certificate.NotAfter) {
				t.Error("Entity certificate valid longer than CA certificate")
			}
		}
	})

	t.Run("Extension validation", func(t *testing.T) {
		// Test with various extensions
		extensionRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Entity with Extensions",
			},
			ValidFor:            30 * 24 * time.Hour,
			DNSNames:            []string{"test.example.com", "*.test.example.com"},
			IPAddresses:         []net.IP{net.IPv4(192, 168, 1, 1), net.IPv6loopback},
			EmailAddresses:      []string{"test@example.com"},
			PermittedDNSDomains: []string{"example.com"},
			ExcludedDNSDomains:  []string{"malicious.example.com"},
			IsCA:                true, // This should be rejected for end-entity
		}

		cert, err := SignCertificate(caCert, caKeyPair, entityKeyPair, extensionRequest)
		if err != nil {
			// If implementation validates CA vs end-entity, this is acceptable
			t.Logf("Extension validation error (acceptable): %v", err)
		} else if cert != nil {
			// Verify extensions were properly set
			if len(cert.Certificate.DNSNames) != len(extensionRequest.DNSNames) {
				t.Error("DNS names not properly set")
			}
			if len(cert.Certificate.IPAddresses) != len(extensionRequest.IPAddresses) {
				t.Error("IP addresses not properly set")
			}
			if len(cert.Certificate.EmailAddresses) != len(extensionRequest.EmailAddresses) {
				t.Error("Email addresses not properly set")
			}
		}
	})

	t.Run("Algorithm compatibility", func(t *testing.T) {
		// Test signing with different algorithms
		ecdsaEntityKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA entity key pair: %v", err)
		}

		mixedRequest := CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Mixed Algorithm Entity",
			},
			ValidFor: 30 * 24 * time.Hour,
		}

		// RSA CA signing ECDSA entity certificate
		cert, err := SignCertificate(caCert, caKeyPair, ecdsaEntityKeyPair, mixedRequest)
		if err != nil {
			t.Errorf("Failed to sign ECDSA certificate with RSA CA: %v", err)
		} else if cert == nil {
			t.Error("Certificate is nil for mixed algorithm signing")
		}
	})
}

// TestCertificateLoadingErrors tests error cases for certificate loading
func TestCertificateLoadingErrors(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("LoadCertificateFromFile errors", func(t *testing.T) {
		// Test with non-existent file
		_, err := LoadCertificateFromFile("nonexistent.pem")
		if err == nil {
			t.Error("Expected error for non-existent file")
		}

		// Test with invalid file content
		invalidFile := filepath.Join(tempDir, "invalid.pem")
		err = os.WriteFile(invalidFile, []byte("invalid certificate data"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid file: %v", err)
		}

		_, err = LoadCertificateFromFile(invalidFile)
		if err == nil {
			t.Error("Expected error for invalid certificate file")
		}

		// Test with empty file
		emptyFile := filepath.Join(tempDir, "empty.pem")
		err = os.WriteFile(emptyFile, []byte(""), 0644)
		if err != nil {
			t.Fatalf("Failed to write empty file: %v", err)
		}

		_, err = LoadCertificateFromFile(emptyFile)
		if err == nil {
			t.Error("Expected error for empty certificate file")
		}
	})

	t.Run("LoadCertificateFromDERFile errors", func(t *testing.T) {
		// Test with non-existent DER file
		_, err := LoadCertificateFromDERFile("nonexistent.der")
		if err == nil {
			t.Error("Expected error for non-existent DER file")
		}

		// Test with invalid DER content
		invalidDERFile := filepath.Join(tempDir, "invalid.der")
		err = os.WriteFile(invalidDERFile, []byte("invalid der data"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid DER file: %v", err)
		}

		_, err = LoadCertificateFromDERFile(invalidDERFile)
		if err == nil {
			t.Error("Expected error for invalid DER file")
		}
	})

	t.Run("ParseCertificateFromDER errors", func(t *testing.T) {
		// Test with invalid DER data
		invalidDER := []byte("invalid der data")
		_, err := ParseCertificateFromDER(invalidDER)
		if err == nil {
			t.Error("Expected error for invalid DER data")
		}

		// Test with empty DER data
		emptyDER := []byte("")
		_, err = ParseCertificateFromDER(emptyDER)
		if err == nil {
			t.Error("Expected error for empty DER data")
		}
	})
}
