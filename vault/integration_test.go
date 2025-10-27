package vault

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestParseCertificateFromPEM(t *testing.T) {
	// Create a valid certificate PEM for testing
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	validPEM := string(certificate.PEMData)

	tests := []struct {
		name    string
		pemData string
		wantErr bool
	}{
		{
			name:    "Valid certificate PEM",
			pemData: validPEM,
			wantErr: false,
		},
		{
			name:    "Empty PEM data",
			pemData: "",
			wantErr: true,
		},
		{
			name:    "Invalid PEM format",
			pemData: "not a valid PEM",
			wantErr: true,
		},
		{
			name:    "Wrong PEM block type",
			pemData: "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----",
			wantErr: true,
		},
		{
			name:    "Invalid certificate data",
			pemData: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificateFromPEM(tt.pemData)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCertificateFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cert == nil {
				t.Error("Expected certificate but got nil")
			}

			if !tt.wantErr && cert != nil {
				if cert.Subject.CommonName != "test.example.com" {
					t.Errorf("Expected CommonName 'test.example.com', got '%s'", cert.Subject.CommonName)
				}
			}
		})
	}
}

func TestParseCertificateChainFromPEM(t *testing.T) {
	// Create a certificate chain for testing
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key pair: %v", err)
	}

	caCert, err := cert.CreateSelfSignedCertificate(caKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "Test CA"},
		IsCA:    true,
	})
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	leafKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf key pair: %v", err)
	}

	leafCert, err := cert.SignCertificate(caCert, caKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, leafKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Create chain PEM (leaf + CA)
	chainPEM := string(leafCert.PEMData) + string(caCert.PEMData)
	singleCertPEM := string(leafCert.PEMData)

	tests := []struct {
		name      string
		pemData   string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "Valid certificate chain",
			pemData:   chainPEM,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "Single certificate",
			pemData:   singleCertPEM,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "Empty PEM data",
			pemData:   "",
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:      "Invalid PEM format",
			pemData:   "not a valid PEM",
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:      "Mixed content (certificate + private key)",
			pemData:   singleCertPEM + "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----",
			wantCount: 1, // Should only parse certificate blocks
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateChainFromPEM(tt.pemData)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCertificateChainFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(certs) != tt.wantCount {
				t.Errorf("Expected %d certificates, got %d", tt.wantCount, len(certs))
			}
		})
	}
}

func TestVaultCertToGoPKI(t *testing.T) {
	// Create test certificates
	rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsaCert, _ := cert.CreateSelfSignedCertificate(rsaKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa.example.com"},
	})

	ed25519KeyPair, _ := algo.GenerateEd25519KeyPair()
	ed25519Cert, _ := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "ed25519.example.com"},
	})

	tests := []struct {
		name     string
		pemCert  string
		pemChain string
		wantErr  bool
		checkAlg x509.PublicKeyAlgorithm
	}{
		{
			name:     "Valid RSA certificate",
			pemCert:  string(rsaCert.PEMData),
			pemChain: string(rsaCert.PEMData),
			wantErr:  false,
			checkAlg: x509.RSA,
		},
		{
			name:     "Valid Ed25519 certificate",
			pemCert:  string(ed25519Cert.PEMData),
			pemChain: "",
			wantErr:  false,
			checkAlg: x509.Ed25519,
		},
		{
			name:     "Invalid PEM certificate",
			pemCert:  "invalid",
			pemChain: "",
			wantErr:  true,
		},
		{
			name:     "Empty certificate",
			pemCert:  "",
			pemChain: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gopkiCert, err := vaultCertToGoPKI(tt.pemCert, tt.pemChain)

			if (err != nil) != tt.wantErr {
				t.Errorf("vaultCertToGoPKI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if gopkiCert == nil {
					t.Error("Expected certificate but got nil")
					return
				}

				if gopkiCert.Certificate == nil {
					t.Error("Certificate.Certificate is nil")
				}

				if len(gopkiCert.PEMData) == 0 {
					t.Error("Certificate.PEMData is empty")
				}

				if len(gopkiCert.DERData) == 0 {
					t.Error("Certificate.DERData is empty")
				}

				if gopkiCert.Certificate.PublicKeyAlgorithm != tt.checkAlg {
					t.Errorf("Expected algorithm %v, got %v", tt.checkAlg, gopkiCert.Certificate.PublicKeyAlgorithm)
				}
			}
		})
	}
}

func TestGopkiCertToPEM(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	pem := gopkiCertToPEM(certificate)

	if len(pem) == 0 {
		t.Error("Expected PEM data but got empty string")
	}

	if !strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----") {
		t.Error("PEM data doesn't start with certificate header")
	}

	if !strings.HasSuffix(strings.TrimSpace(pem), "-----END CERTIFICATE-----") {
		t.Error("PEM data doesn't end with certificate footer")
	}

	// Verify we can parse it back
	parsed, err := parseCertificateFromPEM(pem)
	if err != nil {
		t.Errorf("Failed to parse converted PEM: %v", err)
	}

	if parsed.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CommonName 'test.example.com', got '%s'", parsed.Subject.CommonName)
	}
}

func TestParseCSRFromPEM(t *testing.T) {
	// Create a valid CSR for testing
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	csr, err := cert.CreateCSR(keyPair, cert.CSRRequest{
		Subject: pkix.Name{CommonName: "csr.example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	validCSRPEM := string(csr.PEMData)

	tests := []struct {
		name    string
		pemData string
		wantErr bool
	}{
		{
			name:    "Valid CSR PEM",
			pemData: validCSRPEM,
			wantErr: false,
		},
		{
			name:    "Empty PEM data",
			pemData: "",
			wantErr: true,
		},
		{
			name:    "Invalid PEM format",
			pemData: "not a valid PEM",
			wantErr: true,
		},
		{
			name:    "Wrong PEM block type (certificate)",
			pemData: "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
			wantErr: true,
		},
		{
			name:    "Invalid CSR data",
			pemData: "-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedCSR, err := parseCSRFromPEM(tt.pemData)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCSRFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && parsedCSR == nil {
				t.Error("Expected CSR but got nil")
			}

			if !tt.wantErr && parsedCSR != nil {
				if parsedCSR.Subject.CommonName != "csr.example.com" {
					t.Errorf("Expected CommonName 'csr.example.com', got '%s'", parsedCSR.Subject.CommonName)
				}
			}
		})
	}
}

func TestVaultCertToGoPKI_Ed25519Check(t *testing.T) {
	// Test that Ed25519 certificates are handled correctly
	// (documented limitation for envelope encryption)
	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	ed25519Cert, err := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "ed25519-test.example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to create Ed25519 certificate: %v", err)
	}

	// Should succeed (not an error, just documented limitation)
	gopkiCert, err := vaultCertToGoPKI(string(ed25519Cert.PEMData), "")
	if err != nil {
		t.Errorf("vaultCertToGoPKI() with Ed25519 should not error: %v", err)
	}

	if gopkiCert == nil {
		t.Fatal("Expected certificate but got nil")
	}

	if gopkiCert.Certificate.PublicKeyAlgorithm != x509.Ed25519 {
		t.Errorf("Expected Ed25519 algorithm, got %v", gopkiCert.Certificate.PublicKeyAlgorithm)
	}

	// Verify it's a valid GoPKI certificate despite being Ed25519
	if len(gopkiCert.PEMData) == 0 {
		t.Error("PEMData is empty")
	}
	if len(gopkiCert.DERData) == 0 {
		t.Error("DERData is empty")
	}
}

func TestIntegration_RoundTrip(t *testing.T) {
	// Test full round-trip: GoPKI cert -> PEM -> parse -> GoPKI cert
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalCert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "roundtrip.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"www.roundtrip.example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Convert to PEM
	pemData := gopkiCertToPEM(originalCert)

	// Parse back
	parsedCert, err := vaultCertToGoPKI(pemData, "")
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify data matches
	if parsedCert.Certificate.Subject.CommonName != originalCert.Certificate.Subject.CommonName {
		t.Errorf("CommonName mismatch: got %s, want %s",
			parsedCert.Certificate.Subject.CommonName,
			originalCert.Certificate.Subject.CommonName)
	}

	if len(parsedCert.Certificate.DNSNames) != len(originalCert.Certificate.DNSNames) {
		t.Errorf("DNSNames count mismatch: got %d, want %d",
			len(parsedCert.Certificate.DNSNames),
			len(originalCert.Certificate.DNSNames))
	}

	if string(parsedCert.PEMData) != string(originalCert.PEMData) {
		t.Error("PEM data doesn't match")
	}
}
