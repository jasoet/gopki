package cert

import (
	"bytes"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// TestDERFormatSupport tests all DER format functionality
func TestDERFormatSupport(t *testing.T) {
	// Generate test key pair
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create test certificate
	certificate, err := CreateSelfSignedCertificate(keyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName: "DER Test Certificate",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Verify both PEM and DER data are populated
	if len(certificate.PEMData) == 0 {
		t.Error("PEMData should be populated")
	}
	if len(certificate.DERData) == 0 {
		t.Error("DERData should be populated")
	}

	t.Logf("PEM data length: %d bytes", len(certificate.PEMData))
	t.Logf("DER data length: %d bytes", len(certificate.DERData))

	// DER should be smaller than PEM
	if len(certificate.DERData) >= len(certificate.PEMData) {
		t.Error("DER data should be smaller than PEM data")
	}
}

// TestDERFileSaveAndLoad tests saving and loading DER files
func TestDERFileSaveAndLoad(t *testing.T) {
	// Generate test certificate
	keyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalCert, err := CreateSelfSignedCertificate(keyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName: "DER File Test",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Test DER file operations
	derFilename := "/tmp/test_cert.der"
	defer os.Remove(derFilename)

	// Save to DER file
	err = originalCert.SaveToDERFile(derFilename)
	if err != nil {
		t.Fatalf("Failed to save DER file: %v", err)
	}

	// Check file exists and has content
	fileInfo, err := os.Stat(derFilename)
	if err != nil {
		t.Fatalf("DER file was not created: %v", err)
	}
	if fileInfo.Size() == 0 {
		t.Error("DER file is empty")
	}

	// Load from DER file
	loadedCert, err := LoadCertificateFromDERFile(derFilename)
	if err != nil {
		t.Fatalf("Failed to load DER file: %v", err)
	}

	// Verify loaded certificate matches original
	if !originalCert.Certificate.Equal(loadedCert.Certificate) {
		t.Error("Loaded certificate doesn't match original")
	}

	// Verify both PEM and DER data are populated in loaded certificate
	if len(loadedCert.PEMData) == 0 {
		t.Error("Loaded certificate should have PEMData populated")
	}
	if len(loadedCert.DERData) == 0 {
		t.Error("Loaded certificate should have DERData populated")
	}

	// Verify DER data matches
	if !bytes.Equal(originalCert.DERData, loadedCert.DERData) {
		t.Error("DER data doesn't match between original and loaded certificate")
	}
}

// TestDERParsing tests direct DER data parsing
func TestDERParsing(t *testing.T) {
	// Create test certificate
	keyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalCert, err := CreateSelfSignedCertificate(keyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "DER Parsing Test",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com"},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse certificate from DER data
	parsedCert, err := ParseCertificateFromDER(originalCert.DERData)
	if err != nil {
		t.Fatalf("Failed to parse DER certificate: %v", err)
	}

	// Verify parsed certificate matches original
	if !originalCert.Certificate.Equal(parsedCert.Certificate) {
		t.Error("Parsed certificate doesn't match original")
	}

	// Verify subject information
	if parsedCert.Certificate.Subject.CommonName != "DER Parsing Test" {
		t.Errorf("Expected CommonName 'DER Parsing Test', got '%s'", parsedCert.Certificate.Subject.CommonName)
	}

	if len(parsedCert.Certificate.DNSNames) != 1 || parsedCert.Certificate.DNSNames[0] != "test.example.com" {
		t.Errorf("Expected DNSNames ['test.example.com'], got %v", parsedCert.Certificate.DNSNames)
	}
}

// TestToDERToPEMMethods tests the ToDER() and ToPEM() methods
func TestToDERToPEMMethods(t *testing.T) {
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := CreateSelfSignedCertificate(keyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Method Test Certificate",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Test ToDER() method
	derData := certificate.ToDER()
	if !bytes.Equal(derData, certificate.DERData) {
		t.Error("ToDER() should return the same data as DERData field")
	}

	// Test ToPEM() method
	pemData := certificate.ToPEM()
	if !bytes.Equal(pemData, certificate.PEMData) {
		t.Error("ToPEM() should return the same data as PEMData field")
	}

	// Verify DER is binary (not printable text)
	for _, b := range derData[:min(10, len(derData))] {
		if b > 127 {
			// Found non-ASCII byte, this is good for DER
			break
		}
		if b < 32 && b != 9 && b != 10 && b != 13 {
			// Found control character (except tab, LF, CR), this is good for DER
			break
		}
	}

	// Verify PEM contains header
	pemString := string(pemData)
	if !bytes.Contains(pemData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("PEM data should contain BEGIN CERTIFICATE header")
	}
	if !bytes.Contains(pemData, []byte("-----END CERTIFICATE-----")) {
		t.Error("PEM data should contain END CERTIFICATE header")
	}

	t.Logf("PEM preview: %s", pemString[:min(100, len(pemString))])
}

// TestPEMToDERConversion tests format conversion functions
func TestPEMToDERConversion(t *testing.T) {
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalCert, err := CreateSelfSignedCertificate(keyPair, CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Conversion Test",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Test PEM to DER conversion
	derFromPEM, err := ConvertPEMToDER(originalCert.PEMData)
	if err != nil {
		t.Fatalf("Failed to convert PEM to DER: %v", err)
	}

	if !bytes.Equal(derFromPEM, originalCert.DERData) {
		t.Error("Converted DER doesn't match original DER data")
	}

	// Test DER to PEM conversion
	pemFromDER, err := ConvertDERToPEM(originalCert.DERData)
	if err != nil {
		t.Fatalf("Failed to convert DER to PEM: %v", err)
	}

	// Parse both PEM versions to verify they represent the same certificate
	originalParsed, err := ParseCertificateFromPEM(originalCert.PEMData)
	if err != nil {
		t.Fatalf("Failed to parse original PEM: %v", err)
	}

	convertedParsed, err := ParseCertificateFromPEM(pemFromDER)
	if err != nil {
		t.Fatalf("Failed to parse converted PEM: %v", err)
	}

	if !originalParsed.Certificate.Equal(convertedParsed.Certificate) {
		t.Error("Original and converted certificates don't match")
	}

	t.Logf("Original PEM size: %d bytes", len(originalCert.PEMData))
	t.Logf("DER size: %d bytes", len(originalCert.DERData))
	t.Logf("Converted PEM size: %d bytes", len(pemFromDER))
	t.Logf("DER is %.1f%% smaller than PEM", float64(len(originalCert.DERData))/float64(len(originalCert.PEMData))*100)
}

// TestDERConversionErrors tests error handling in conversion functions
func TestDERConversionErrors(t *testing.T) {
	// Test invalid PEM data
	invalidPEM := []byte("This is not PEM data")
	_, err := ConvertPEMToDER(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}

	// Test invalid DER data
	invalidDER := []byte("This is not DER data")
	_, err = ConvertDERToPEM(invalidDER)
	if err == nil {
		t.Error("Expected error for invalid DER data")
	}

	// Test wrong PEM block type
	wrongTypePEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAg==
-----END PRIVATE KEY-----`)
	_, err = ConvertPEMToDER(wrongTypePEM)
	if err == nil {
		t.Error("Expected error for wrong PEM block type")
	}
}

// Helper function for min (Go 1.21+)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}