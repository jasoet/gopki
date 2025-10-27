package cert

import (
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair/algo"
)

func TestCreateCSR(t *testing.T) {
	tests := []struct {
		name       string
		genKeyPair func() (interface{}, error)
		request    CSRRequest
		wantErr    bool
		checkDNS   bool
	}{
		{
			name:       "RSA 2048 CSR with DNS names",
			genKeyPair: func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName:   "test.example.com",
					Organization: []string{"Test Org"},
					Country:      []string{"US"},
				},
				DNSNames: []string{"test.example.com", "www.test.example.com"},
			},
			wantErr:  false,
			checkDNS: true,
		},
		{
			name:       "ECDSA P-256 CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName:   "ecdsa.example.com",
					Organization: []string{"Test Org"},
				},
			},
			wantErr: false,
		},
		{
			name:       "Ed25519 CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateEd25519KeyPair() },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName: "ed25519.example.com",
				},
			},
			wantErr: false,
		},
		{
			name:       "CSR with IP addresses",
			genKeyPair: func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName: "server.local",
				},
				IPAddresses: []net.IP{
					net.ParseIP("192.168.1.100"),
					net.ParseIP("10.0.0.1"),
				},
			},
			wantErr: false,
		},
		{
			name:       "CSR with email addresses",
			genKeyPair: func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName: "user@example.com",
				},
				EmailAddress: []string{"user@example.com", "admin@example.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := tt.genKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair: %v", err)
			}

			var csr *CertificateSigningRequest
			switch kp := keyPair.(type) {
			case *algo.RSAKeyPair:
				csr, err = CreateCSR(kp, tt.request)
			case *algo.ECDSAKeyPair:
				csr, err = CreateCSR(kp, tt.request)
			case *algo.Ed25519KeyPair:
				csr, err = CreateCSR(kp, tt.request)
			default:
				t.Fatalf("Unknown key pair type: %T", kp)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify CSR was created
			if csr == nil {
				t.Error("CreateCSR() returned nil CSR")
				return
			}

			// Verify PEM and DER data exist
			if len(csr.PEMData) == 0 {
				t.Error("CSR PEMData is empty")
			}
			if len(csr.DERData) == 0 {
				t.Error("CSR DERData is empty")
			}

			// Verify CSR signature is valid
			if err := csr.Request.CheckSignature(); err != nil {
				t.Errorf("CSR signature verification failed: %v", err)
			}

			// Verify subject
			if csr.Request.Subject.CommonName != tt.request.Subject.CommonName {
				t.Errorf("CommonName = %v, want %v", csr.Request.Subject.CommonName, tt.request.Subject.CommonName)
			}

			// Verify DNS names if specified
			if tt.checkDNS && len(csr.Request.DNSNames) != len(tt.request.DNSNames) {
				t.Errorf("DNS names count = %v, want %v", len(csr.Request.DNSNames), len(tt.request.DNSNames))
			}
		})
	}
}

func TestCreateCACSR(t *testing.T) {
	tests := []struct {
		name       string
		genKeyPair func() (interface{}, error)
		request    CSRRequest
		wantErr    bool
	}{
		{
			name:       "RSA 4096 CA CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize4096) },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName:   "Intermediate CA",
					Organization: []string{"Test Org"},
					Country:      []string{"US"},
				},
				IsCA:       true,
				MaxPathLen: 0,
			},
			wantErr: false,
		},
		{
			name:       "ECDSA P-384 CA CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P384) },
			request: CSRRequest{
				Subject: pkix.Name{
					CommonName:   "ECDSA Intermediate CA",
					Organization: []string{"Test Org"},
				},
				IsCA:       true,
				MaxPathLen: 1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := tt.genKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair: %v", err)
			}

			var csr *CertificateSigningRequest
			switch kp := keyPair.(type) {
			case *algo.RSAKeyPair:
				csr, err = CreateCACSR(kp, tt.request)
			case *algo.ECDSAKeyPair:
				csr, err = CreateCACSR(kp, tt.request)
			case *algo.Ed25519KeyPair:
				csr, err = CreateCACSR(kp, tt.request)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCACSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify CSR was created
			if csr == nil {
				t.Error("CreateCACSR() returned nil CSR")
				return
			}

			// Verify signature
			if err := csr.Request.CheckSignature(); err != nil {
				t.Errorf("CA CSR signature verification failed: %v", err)
			}
		})
	}
}

func TestCSRSaveAndLoad(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()
	csrPath := filepath.Join(tmpDir, "test.csr")

	// Generate key pair and CSR
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	csr, err := CreateCSR(keyPair, CSRRequest{
		Subject: pkix.Name{
			CommonName: "save-load-test.example.com",
		},
	})
	if err != nil {
		t.Fatalf("CreateCSR() failed: %v", err)
	}

	// Save CSR to file
	if err := csr.SaveToFile(csrPath); err != nil {
		t.Fatalf("SaveToFile() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(csrPath); os.IsNotExist(err) {
		t.Errorf("CSR file was not created: %s", csrPath)
	}

	// Load CSR from file
	loadedCSR, err := LoadCSRFromFile(csrPath)
	if err != nil {
		t.Fatalf("LoadCSRFromFile() failed: %v", err)
	}

	// Verify loaded CSR matches original
	if loadedCSR.Request.Subject.CommonName != csr.Request.Subject.CommonName {
		t.Errorf("Loaded CSR CommonName = %v, want %v",
			loadedCSR.Request.Subject.CommonName,
			csr.Request.Subject.CommonName)
	}

	// Verify signature of loaded CSR
	if err := loadedCSR.Request.CheckSignature(); err != nil {
		t.Errorf("Loaded CSR signature verification failed: %v", err)
	}
}

func TestParseCSRFromPEM(t *testing.T) {
	// Generate key pair and create CSR
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	originalCSR, err := CreateCSR(keyPair, CSRRequest{
		Subject: pkix.Name{
			CommonName: "parse-test.example.com",
		},
	})
	if err != nil {
		t.Fatalf("CreateCSR() failed: %v", err)
	}

	// Parse from PEM data
	parsedCSR, err := ParseCSRFromPEM(originalCSR.PEMData)
	if err != nil {
		t.Fatalf("ParseCSRFromPEM() failed: %v", err)
	}

	// Verify parsed CSR matches original
	if parsedCSR.Request.Subject.CommonName != originalCSR.Request.Subject.CommonName {
		t.Errorf("Parsed CSR CommonName = %v, want %v",
			parsedCSR.Request.Subject.CommonName,
			originalCSR.Request.Subject.CommonName)
	}

	// Test invalid PEM
	_, err = ParseCSRFromPEM([]byte("invalid pem data"))
	if err == nil {
		t.Error("ParseCSRFromPEM() should fail with invalid PEM data")
	}
}

func TestSignCSR(t *testing.T) {
	// Create CA certificate
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize4096)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	caCert, err := CreateCACertificate(caKeyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		IsCA:       true,
		MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("CreateCACertificate() failed: %v", err)
	}

	tests := []struct {
		name        string
		genKeyPair  func() (interface{}, error)
		csrRequest  CSRRequest
		certRequest CertificateRequest
		wantErr     bool
	}{
		{
			name:       "Sign RSA CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) },
			csrRequest: CSRRequest{
				Subject: pkix.Name{
					CommonName: "server.example.com",
				},
				DNSNames: []string{"server.example.com", "www.example.com"},
			},
			certRequest: CertificateRequest{
				ValidFor: 365 * 24 * time.Hour,
			},
			wantErr: false,
		},
		{
			name:       "Sign ECDSA CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) },
			csrRequest: CSRRequest{
				Subject: pkix.Name{
					CommonName: "ecdsa-server.example.com",
				},
			},
			certRequest: CertificateRequest{
				ValidFor: 365 * 24 * time.Hour,
			},
			wantErr: false,
		},
		{
			name:       "Sign Ed25519 CSR",
			genKeyPair: func() (interface{}, error) { return algo.GenerateEd25519KeyPair() },
			csrRequest: CSRRequest{
				Subject: pkix.Name{
					CommonName: "ed25519-server.example.com",
				},
			},
			certRequest: CertificateRequest{
				ValidFor: 365 * 24 * time.Hour,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key pair
			keyPair, err := tt.genKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair: %v", err)
			}

			// Create CSR
			var csr *CertificateSigningRequest
			switch kp := keyPair.(type) {
			case *algo.RSAKeyPair:
				csr, err = CreateCSR(kp, tt.csrRequest)
			case *algo.ECDSAKeyPair:
				csr, err = CreateCSR(kp, tt.csrRequest)
			case *algo.Ed25519KeyPair:
				csr, err = CreateCSR(kp, tt.csrRequest)
			}
			if err != nil {
				t.Fatalf("CreateCSR() failed: %v", err)
			}

			// Sign CSR with CA
			cert, err := SignCSR(caCert, caKeyPair, csr, tt.certRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify certificate was created
			if cert == nil {
				t.Error("SignCSR() returned nil certificate")
				return
			}

			// Verify certificate subject matches CSR
			if cert.Certificate.Subject.CommonName != tt.csrRequest.Subject.CommonName {
				t.Errorf("Certificate CommonName = %v, want %v",
					cert.Certificate.Subject.CommonName,
					tt.csrRequest.Subject.CommonName)
			}

			// Verify certificate was signed by CA
			if err := VerifyCertificate(cert, caCert); err != nil {
				t.Errorf("Certificate verification failed: %v", err)
			}

			// Verify DNS names if present
			if len(tt.csrRequest.DNSNames) > 0 {
				if len(cert.Certificate.DNSNames) != len(tt.csrRequest.DNSNames) {
					t.Errorf("Certificate DNSNames count = %v, want %v",
						len(cert.Certificate.DNSNames),
						len(tt.csrRequest.DNSNames))
				}
			}
		})
	}
}

func TestSignCSR_InvalidSignature(t *testing.T) {
	// Create CA
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize4096)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	caCert, err := CreateCACertificate(caKeyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		IsCA: true,
	})
	if err != nil {
		t.Fatalf("CreateCACertificate() failed: %v", err)
	}

	// Create valid CSR
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	csr, err := CreateCSR(keyPair, CSRRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	})
	if err != nil {
		t.Fatalf("CreateCSR() failed: %v", err)
	}

	// Corrupt the CSR signature (modify the last byte)
	csr.Request.Signature[len(csr.Request.Signature)-1] ^= 0xFF

	// Try to sign corrupted CSR - should fail
	_, err = SignCSR(caCert, caKeyPair, csr, CertificateRequest{
		ValidFor: 365 * 24 * time.Hour,
	})
	if err == nil {
		t.Error("SignCSR() should fail with invalid CSR signature")
	}
}

func TestCSRWorkflow_EndToEnd(t *testing.T) {
	// This test simulates the complete CSR workflow:
	// 1. Entity generates key pair and CSR
	// 2. Entity submits CSR to CA
	// 3. CA signs CSR and returns certificate
	// 4. Entity verifies certificate

	// Step 1: Entity generates key pair and CSR
	entityKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	csr, err := CreateCSR(entityKeyPair, CSRRequest{
		Subject: pkix.Name{
			CommonName:   "application.example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		DNSNames:    []string{"application.example.com", "app.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
	})
	if err != nil {
		t.Fatalf("CreateCSR() failed: %v", err)
	}

	// Step 2: CA receives CSR and verifies it
	if err := csr.Request.CheckSignature(); err != nil {
		t.Fatalf("CSR signature verification failed: %v", err)
	}

	// CA has its own certificate
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize4096)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() failed: %v", err)
	}

	caCert, err := CreateCACertificate(caKeyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Example Root CA",
			Organization: []string{"Example Corp"},
		},
		IsCA:       true,
		MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("CreateCACertificate() failed: %v", err)
	}

	// Step 3: CA signs the CSR
	cert, err := SignCSR(caCert, caKeyPair, csr, CertificateRequest{
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("SignCSR() failed: %v", err)
	}

	// Step 4: Entity verifies the certificate
	if err := VerifyCertificate(cert, caCert); err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}

	// Verify all attributes are correct
	if cert.Certificate.Subject.CommonName != "application.example.com" {
		t.Errorf("Certificate CommonName incorrect")
	}
	if len(cert.Certificate.DNSNames) != 2 {
		t.Errorf("Certificate DNSNames count incorrect")
	}
	if len(cert.Certificate.IPAddresses) != 1 {
		t.Errorf("Certificate IPAddresses count incorrect")
	}

	// Verify certificate is signed by CA
	if cert.Certificate.Issuer.CommonName != caCert.Certificate.Subject.CommonName {
		t.Errorf("Certificate issuer mismatch")
	}
}
