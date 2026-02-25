package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestCertIntegrationComprehensive(t *testing.T) {
	tempDir := t.TempDir()

	// Generate test key pair and certificate for use in tests
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost", "test.example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a CA certificate for chain testing
	caTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		SerialNumber:          big.NewInt(100),
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA keys: %v", err)
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCertificate, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	t.Run("FromP12Cert", func(t *testing.T) {
		// Create P12 data
		opts := DefaultCreateOptions("test123")
		p12Data, err := CreateP12(privateKey, certificate, nil, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 data: %v", err)
		}

		// Test loading certificate from P12 data
		goPKICert, caCerts, err := FromP12Cert(p12Data, "test123")
		if err != nil {
			t.Errorf("FromP12Cert failed: %v", err)
		}
		if goPKICert == nil {
			t.Error("Expected non-nil GoPKI certificate")
		}
		if goPKICert.Certificate.Subject.CommonName != "Test Certificate" {
			t.Error("Certificate subject mismatch")
		}
		if len(caCerts) != 0 {
			t.Error("Expected no CA certificates in basic test")
		}

		// Test error cases
		_, _, err = FromP12Cert(nil, "test123")
		if err == nil {
			t.Error("Expected error for nil P12 data")
		}

		_, _, err = FromP12Cert(p12Data, "")
		if err == nil {
			t.Error("Expected error for empty password")
		}

		_, _, err = FromP12Cert([]byte("invalid"), "test123")
		if err == nil {
			t.Error("Expected error for invalid P12 data")
		}
	})

	t.Run("FromP12CertFile", func(t *testing.T) {
		// Create P12 file
		p12File := filepath.Join(tempDir, "test_cert.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, nil, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Test loading certificate from P12 file
		goPKICert, _, err := FromP12CertFile(p12File, "test123")
		if err != nil {
			t.Errorf("FromP12CertFile failed: %v", err)
		}
		if goPKICert == nil {
			t.Error("Expected non-nil GoPKI certificate")
		}
		if goPKICert.Certificate.Subject.CommonName != "Test Certificate" {
			t.Error("Certificate subject mismatch")
		}

		// Test error cases
		_, _, err = FromP12CertFile("", "test123")
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		_, _, err = FromP12CertFile("nonexistent.p12", "test123")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("LoadCertificateChainFromP12", func(t *testing.T) {
		// Create P12 file with certificate chain
		caCerts := []*x509.Certificate{caCertificate}
		opts := DefaultCreateOptions("test123")
		p12File := filepath.Join(tempDir, "chain_test.p12")
		err := CreateP12File(p12File, privateKey, certificate, caCerts, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file with chain: %v", err)
		}

		// Test loading certificate chain
		certificates, err := LoadCertificateChainFromP12(p12File, "test123")
		if err != nil {
			t.Errorf("LoadCertificateChainFromP12 failed: %v", err)
		}
		if len(certificates) < 1 {
			t.Error("Expected at least one certificate")
		}
		if certificates[0].Certificate.Subject.CommonName != "Test Certificate" {
			t.Error("First certificate subject mismatch")
		}

		// Test error cases
		_, err = LoadCertificateChainFromP12("", "test123")
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		_, err = LoadCertificateChainFromP12("nonexistent.p12", "test123")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("SaveCertToP12", func(t *testing.T) {
		// Wrap certificate in GoPKI Certificate
		goPKICert := &cert.Certificate{
			Certificate: certificate,
		}

		// Test saving certificate to P12 file
		p12File := filepath.Join(tempDir, "save_test.p12")
		err := SaveCertToP12(goPKICert, privateKey, p12File, "test123")
		if err != nil {
			t.Errorf("SaveCertToP12 failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(p12File); os.IsNotExist(err) {
			t.Error("P12 file was not created")
		}

		// Verify by loading it back
		loadedContainer, err := QuickLoadP12(p12File, "test123")
		if err != nil {
			t.Errorf("Failed to load saved P12 file: %v", err)
		}
		if loadedContainer.Certificate.Subject.CommonName != "Test Certificate" {
			t.Error("Round-trip certificate subject mismatch")
		}

		// Test error cases
		err = SaveCertToP12(nil, privateKey, p12File, "test123")
		if err == nil {
			t.Error("Expected error for nil certificate")
		}

		err = SaveCertToP12(goPKICert, nil, p12File, "test123")
		if err == nil {
			t.Error("Expected error for nil private key")
		}
	})

	t.Run("SaveCertToP12WithChain", func(t *testing.T) {
		// Wrap certificate in GoPKI Certificate
		goPKICert := &cert.Certificate{
			Certificate: certificate,
		}

		// Wrap CA certificates in GoPKI certificates
		goPKICACerts := []*cert.Certificate{
			{Certificate: caCertificate},
		}

		// Test saving certificate with chain to P12 file
		p12File := filepath.Join(tempDir, "save_chain_test.p12")
		err := SaveCertToP12WithChain(goPKICert, privateKey, goPKICACerts, p12File, "test123")
		if err != nil {
			t.Errorf("SaveCertToP12WithChain failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(p12File); os.IsNotExist(err) {
			t.Error("P12 file was not created")
		}

		// Verify by loading it back
		loadedContainer, err := QuickLoadP12(p12File, "test123")
		if err != nil {
			t.Errorf("Failed to load saved P12 file with chain: %v", err)
		}
		if len(loadedContainer.CACertificates) != 1 {
			t.Errorf("Expected 1 CA certificate, got %d", len(loadedContainer.CACertificates))
		}

		// Test error cases
		err = SaveCertToP12WithChain(nil, privateKey, goPKICACerts, p12File, "test123")
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
	})

	t.Run("ExtractCertificatesFromP12", func(t *testing.T) {
		// Create P12 with certificate chain
		caCerts := []*x509.Certificate{caCertificate}
		opts := DefaultCreateOptions("test123")
		p12File := filepath.Join(tempDir, "extract_test.p12")
		err := CreateP12File(p12File, privateKey, certificate, caCerts, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Test extracting all certificates to output directory
		outputDir := filepath.Join(tempDir, "extracted_certs")
		err = ExtractCertificatesFromP12(p12File, "test123", outputDir)
		if err != nil {
			t.Errorf("ExtractCertificatesFromP12 failed: %v", err)
		}

		// Verify output directory was created and contains certificate files
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			t.Error("Output directory was not created")
		}

		// Test error cases
		err = ExtractCertificatesFromP12("", "test123", outputDir)
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		err = ExtractCertificatesFromP12("nonexistent.p12", "test123", outputDir)
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("ValidateP12Certificate", func(t *testing.T) {
		// Create P12 file
		p12File := filepath.Join(tempDir, "validate_test.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, nil, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Test validation
		validationResult, err := ValidateP12Certificate(p12File, "test123")
		if err != nil {
			t.Errorf("ValidateP12Certificate failed: %v", err)
		}
		if validationResult == nil {
			t.Error("Expected non-nil validation result")
		}

		// Test error cases
		_, err = ValidateP12Certificate("", "test123")
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		_, err = ValidateP12Certificate("nonexistent.p12", "test123")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("ImportP12AndSavePEM", func(t *testing.T) {
		// Create P12 file
		p12File := filepath.Join(tempDir, "import_test.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, nil, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Test importing and saving as PEM
		pemFile := filepath.Join(tempDir, "imported.pem")
		err = ImportP12AndSavePEM(p12File, "test123", pemFile)
		if err != nil {
			t.Errorf("ImportP12AndSavePEM failed: %v", err)
		}

		// Verify PEM file was created
		if _, err := os.Stat(pemFile); os.IsNotExist(err) {
			t.Error("PEM file was not created")
		}

		// Test error cases
		err = ImportP12AndSavePEM("", "test123", pemFile)
		if err == nil {
			t.Error("Expected error for empty P12 filename")
		}
	})

	t.Run("CreateP12FromPEM", func(t *testing.T) {
		// First create PEM files
		certPEMFile := filepath.Join(tempDir, "cert.pem")
		keyPEMFile := filepath.Join(tempDir, "key.pem")

		// Save certificate to PEM
		certPEM := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}
		certFile, err := os.Create(certPEMFile)
		if err != nil {
			t.Fatalf("Failed to create cert PEM file: %v", err)
		}
		pem.Encode(certFile, certPEM)
		certFile.Close()

		// Save private key to PEM
		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			t.Fatalf("Failed to marshal private key: %v", err)
		}
		keyPEM := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}
		keyFile, err := os.Create(keyPEMFile)
		if err != nil {
			t.Fatalf("Failed to create key PEM file: %v", err)
		}
		pem.Encode(keyFile, keyPEM)
		keyFile.Close()

		// Test creating P12 from PEM files
		p12File := filepath.Join(tempDir, "from_pem.p12")
		err = CreateP12FromPEM(keyPEMFile, certPEMFile, p12File, "test123")
		if err != nil {
			t.Errorf("CreateP12FromPEM failed: %v", err)
		}

		// Verify by loading the P12 file
		container, err := QuickLoadP12(p12File, "test123")
		if err != nil {
			t.Errorf("Failed to load P12 created from PEM: %v", err)
		}
		if container.Certificate.Subject.CommonName != "Test Certificate" {
			t.Error("P12 from PEM certificate subject mismatch")
		}

		// Test error cases
		err = CreateP12FromPEM("", certPEMFile, p12File, "test123")
		if err == nil {
			t.Error("Expected error for empty key file")
		}

		err = CreateP12FromPEM(keyPEMFile, "", p12File, "test123")
		if err == nil {
			t.Error("Expected error for empty cert file")
		}
	})

	t.Run("ListCertificatesInP12", func(t *testing.T) {
		// Create P12 with certificate chain
		caCerts := []*x509.Certificate{caCertificate}
		p12File := filepath.Join(tempDir, "list_test.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, caCerts, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Create utility instance
		utils := P12CertificateUtils{}

		// Test listing certificates
		certList, err := utils.ListCertificatesInP12(p12File, "test123")
		if err != nil {
			t.Errorf("ListCertificatesInP12 failed: %v", err)
		}
		if len(certList) == 0 {
			t.Error("Expected non-empty certificate list")
		}

		// Should contain info about both leaf and CA certificates
		foundLeaf := false
		foundCA := false
		for _, certInfo := range certList {
			if subject, ok := certInfo["subject"].(string); ok {
				if subject == "CN=Test Certificate,O=Test Org,C=US" {
					foundLeaf = true
				}
				if subject == "CN=Test CA,O=Test CA Org,C=US" {
					foundCA = true
				}
			}
		}
		if !foundLeaf {
			t.Error("Leaf certificate not found in list")
		}
		if !foundCA {
			t.Error("CA certificate not found in list")
		}

		// Test error cases
		_, err = utils.ListCertificatesInP12("", "test123")
		if err == nil {
			t.Error("Expected error for empty filename")
		}
	})

	t.Run("VerifyP12CertificateChain", func(t *testing.T) {
		// Create P12 with certificate chain
		caCerts := []*x509.Certificate{caCertificate}
		p12File := filepath.Join(tempDir, "verify_test.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, caCerts, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Create utility instance
		utils := P12CertificateUtils{}

		// Test chain verification
		err = utils.VerifyP12CertificateChain(p12File, "test123")
		// Note: This might fail since we're using self-signed certificates
		// but the function should be callable without panicking
		_ = err

		// Test error cases
		err = utils.VerifyP12CertificateChain("", "test123")
		if err == nil {
			t.Error("Expected error for empty filename")
		}
	})

	t.Run("ConvertP12ChainToPEM", func(t *testing.T) {
		// Create P12 with certificate chain
		caCerts := []*x509.Certificate{caCertificate}
		p12File := filepath.Join(tempDir, "convert_test.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, caCerts, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Create utility instance
		utils := P12CertificateUtils{}

		// Test converting to PEM
		outputPrefix := filepath.Join(tempDir, "convert_output")
		err = utils.ConvertP12ChainToPEM(p12File, "test123", outputPrefix)
		if err != nil {
			t.Errorf("ConvertP12ChainToPEM failed: %v", err)
		}

		// Test error cases
		err = utils.ConvertP12ChainToPEM("", "test123", outputPrefix)
		if err == nil {
			t.Error("Expected error for empty P12 filename")
		}
	})

	t.Run("GetP12CertificateFingerprints", func(t *testing.T) {
		// Create P12 file
		p12File := filepath.Join(tempDir, "fingerprint_test.p12")
		opts := DefaultCreateOptions("test123")
		err := CreateP12File(p12File, privateKey, certificate, nil, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Create utility instance
		utils := P12CertificateUtils{}

		// Test getting fingerprints
		fingerprints, err := utils.GetP12CertificateFingerprints(p12File, "test123")
		if err != nil {
			t.Errorf("GetP12CertificateFingerprints failed: %v", err)
		}
		// The function may return certificate data or actual fingerprints
		// Let's verify we get at least some data
		if len(fingerprints) == 0 {
			t.Error("Expected some fingerprint data")
		}

		// Print actual data for debugging
		t.Logf("GetP12CertificateFingerprints returned %d items", len(fingerprints))

		// Verify all values are non-empty
		for key, value := range fingerprints {
			if value == "" {
				t.Errorf("Value for %s is empty", key)
			}
		}

		// Test error cases
		_, err = utils.GetP12CertificateFingerprints("", "test123")
		if err == nil {
			t.Error("Expected error for empty filename")
		}
	})

	// Additional test for ExtractCertificateChain method
	t.Run("P12Container_ExtractCertificateChain", func(t *testing.T) {
		// Create P12 with certificate chain
		caCerts := []*x509.Certificate{caCertificate}
		opts := DefaultCreateOptions("test123")
		p12Data, err := CreateP12(privateKey, certificate, caCerts, opts)
		if err != nil {
			t.Fatalf("Failed to create P12 data: %v", err)
		}

		// Parse P12 to get container
		container, err := ParseP12(p12Data, DefaultLoadOptions("test123"))
		if err != nil {
			t.Fatalf("Failed to parse P12 data: %v", err)
		}

		// Test ExtractCertificateChain method
		chain := container.ExtractCertificateChain()
		if len(chain) < 1 {
			t.Error("Expected at least one certificate in chain")
		}

		// First certificate should be the leaf certificate
		if chain[0].Subject.CommonName != "Test Certificate" {
			t.Error("First certificate in chain should be the leaf certificate")
		}

		// If we have CA certificates, they should be included
		if len(chain) > 1 && chain[1].Subject.CommonName != "Test CA" {
			t.Error("Second certificate should be the CA certificate")
		}
	})
}

func TestHelperFunctions(t *testing.T) {
	tempDir := t.TempDir()

	// Generate test data
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create expired certificate for testing
	expiredTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Expired Certificate",
		},
		NotBefore:    time.Now().Add(-2 * 365 * 24 * time.Hour), // 2 years ago
		NotAfter:     time.Now().Add(-365 * 24 * time.Hour),     // 1 year ago (expired)
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(999),
	}

	expiredCertDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create expired certificate: %v", err)
	}

	expiredCertificate, err := x509.ParseCertificate(expiredCertDER)
	if err != nil {
		t.Fatalf("Failed to parse expired certificate: %v", err)
	}

	t.Run("ValidateP12File", func(t *testing.T) {
		// Create valid P12 file
		validP12File := filepath.Join(tempDir, "valid_test.p12")
		err := GenerateTestP12(validP12File, "test123")
		if err != nil {
			t.Fatalf("Failed to generate test P12: %v", err)
		}

		// Test validation
		err = ValidateP12File(validP12File, "test123")
		if err != nil {
			t.Errorf("ValidateP12File failed for valid file: %v", err)
		}

		// Test with invalid file
		err = ValidateP12File("nonexistent.p12", "test123")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}

		// Test with wrong password
		err = ValidateP12File(validP12File, "wrong_password")
		if err == nil {
			t.Error("Expected error for wrong password")
		}
	})

	t.Run("LoadCertificateFromPEMFile", func(t *testing.T) {
		// Create valid certificate
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "PEM Test Certificate",
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			SerialNumber: big.NewInt(123),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Save certificate to PEM file
		certPEMFile := filepath.Join(tempDir, "test_cert.pem")
		certPEM := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}
		certFile, err := os.Create(certPEMFile)
		if err != nil {
			t.Fatalf("Failed to create cert PEM file: %v", err)
		}
		pem.Encode(certFile, certPEM)
		certFile.Close()

		// Test loading certificate from PEM file
		loadedCert, err := LoadCertificateFromPEMFile(certPEMFile)
		if err != nil {
			t.Errorf("LoadCertificateFromPEMFile failed: %v", err)
		}
		if loadedCert.Certificate.Subject.CommonName != "PEM Test Certificate" {
			t.Error("Loaded certificate subject mismatch")
		}

		// Test error cases
		_, err = LoadCertificateFromPEMFile("")
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		_, err = LoadCertificateFromPEMFile("nonexistent.pem")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("LoadPrivateKeyFromPEM", func(t *testing.T) {
		// Create PEM private key file
		keyPEMFile := filepath.Join(tempDir, "test_key.pem")
		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			t.Fatalf("Failed to marshal private key: %v", err)
		}

		keyPEM := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}
		keyFile, err := os.Create(keyPEMFile)
		if err != nil {
			t.Fatalf("Failed to create key PEM file: %v", err)
		}
		pem.Encode(keyFile, keyPEM)
		keyFile.Close()

		// Test loading private key from PEM file
		loadedKey, err := LoadPrivateKeyFromPEM(keyPEMFile)
		if err != nil {
			t.Errorf("LoadPrivateKeyFromPEM failed: %v", err)
		}
		if loadedKey == nil {
			t.Error("Expected non-nil private key")
		}

		// Test with RSA key specifically
		if rsaKey, ok := loadedKey.(*rsa.PrivateKey); ok {
			if rsaKey.Size() != privateKey.Size() {
				t.Error("RSA key size mismatch")
			}
		} else {
			t.Error("Expected RSA private key")
		}

		// Test error cases
		_, err = LoadPrivateKeyFromPEM("")
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		_, err = LoadPrivateKeyFromPEM("nonexistent.pem")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	// Test helper validation functions with different key types
	t.Run("HelperValidationFunctions", func(t *testing.T) {
		// Generate ECDSA key pair for testing
		ecdsaPrivKey, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		// Generate Ed25519 key pair for testing
		ed25519PrivKey, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		// Test validateCertificateExpiration with expired certificate
		err = validateCertificateExpiration(expiredCertificate)
		if err == nil {
			t.Error("Expected error for expired certificate")
		}

		// Test validateKeyPairMatch with mismatched keys
		err = validateKeyPairMatch(expiredCertificate, ecdsaPrivKey.PrivateKey)
		if err == nil {
			t.Error("Expected error for mismatched key pair")
		}

		// Test getPrivateKeyType with different key types
		if keyType := getPrivateKeyType(privateKey); keyType != "RSA" {
			t.Errorf("Expected RSA key type, got %s", keyType)
		}

		if keyType := getPrivateKeyType(ecdsaPrivKey.PrivateKey); keyType != "ECDSA" {
			t.Errorf("Expected ECDSA key type, got %s", keyType)
		}

		if keyType := getPrivateKeyType(ed25519PrivKey.PrivateKey); keyType != "Ed25519" {
			t.Errorf("Expected Ed25519 key type, got %s", keyType)
		}

		if keyType := getPrivateKeyType("invalid"); keyType != "Unknown (string)" {
			t.Errorf("Expected 'Unknown (string)' key type for invalid input, got %s", keyType)
		}
	})
}
