//go:build compatibility

package bao_test

import (
	"crypto/x509"
	"testing"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/pkcs12"
)

func TestPKCS12_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("Bundle_Creation", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Cert_Key_To_PKCS12", testBaoCertKeyToPKCS12)
		t.Run("Bao_Cert_Chain_To_PKCS12", testBaoCertChainToPKCS12)
	})

	t.Run("Bundle_Parsing", func(t *testing.T) {
		t.Parallel()
		t.Run("PKCS12_Parse_Bao_Materials", testPKCS12ParseBaoMaterials)
		t.Run("PKCS12_Extract_Reimport_Bao", testPKCS12ExtractReimportBao)
	})

	t.Run("Integration", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Issue_PKCS12_Export", testBaoIssuePKCS12Export)
	})
}

// testBaoCertKeyToPKCS12 tests creating PKCS#12 bundles from Bao certificates and keys.
func testBaoCertKeyToPKCS12(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Create PKCS#12 bundle
	password := "test-password"
	pfxData, err := pkcs12.Create(keyPair, certificate, nil, password, pkcs12.Options{
		FriendlyName: "Bao Certificate",
	})
	if err != nil {
		t.Fatalf("Failed to create PKCS#12: %v", err)
	}

	// Parse PKCS#12 to verify
	parsedKey, parsedCert, parsedCAs, err := pkcs12.Parse(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	if parsedCert.Certificate.Subject.CommonName != certificate.Certificate.Subject.CommonName {
		t.Errorf("Certificate CN mismatch after PKCS#12 roundtrip")
	}

	if parsedKey == nil {
		t.Errorf("Private key not present in PKCS#12")
	}

	if parsedCAs != nil && len(parsedCAs) > 0 {
		t.Logf("CA certificates included: %d", len(parsedCAs))
	}

	t.Logf("✓ Successfully created PKCS#12 from Bao certificate and key")
}

// testBaoCertChainToPKCS12 tests creating PKCS#12 with Bao certificate chains.
func testBaoCertChainToPKCS12(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Create root CA
	rootCA, err := CreateTestRootCA(env.Ctx, env.Client, "root-ca", "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	rootCert, err := rootCA.Certificate()
	if err != nil {
		t.Fatalf("Failed to get root cert: %v", err)
	}

	// Create intermediate CA
	intermediateCA, err := CreateTestIntermediateCA(env.Ctx, env.Client, rootCA, "intermediate-ca", "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	intermediateCert, err := intermediateCA.Certificate()
	if err != nil {
		t.Fatalf("Failed to get intermediate cert: %v", err)
	}

	// Generate key and issue end-entity certificate
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	err = intermediateCA.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Create PKCS#12 with full chain
	password := "test-password"
	caCerts := []*x509.Certificate{intermediateCert, rootCert}
	pfxData, err := pkcs12.Create(keyPair, certificate, caCerts, password, pkcs12.Options{
		FriendlyName: "Bao Certificate with Chain",
	})
	if err != nil {
		t.Fatalf("Failed to create PKCS#12 with chain: %v", err)
	}

	// Parse PKCS#12 to verify chain
	parsedKey, parsedCert, parsedCAs, err := pkcs12.Parse(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	if parsedCert.Certificate.Subject.CommonName != certificate.Certificate.Subject.CommonName {
		t.Errorf("Certificate CN mismatch")
	}

	if parsedKey == nil {
		t.Errorf("Private key not present")
	}

	if len(parsedCAs) != 2 {
		t.Errorf("Expected 2 CA certificates, got %d", len(parsedCAs))
	}

	t.Logf("✓ Successfully created PKCS#12 with Bao certificate chain")
}

// testPKCS12ParseBaoMaterials tests parsing PKCS#12 bundles created from Bao materials.
func testPKCS12ParseBaoMaterials(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Get CA cert
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	// Create PKCS#12
	password := "test-password"
	pfxData, err := pkcs12.Create(keyPair,certificate.Certificate, []*x509.Certificate{caCert}, password, pkcs12.Options{
		FriendlyName: "Test Bundle",
	})
	if err != nil {
		t.Fatalf("Failed to create PKCS#12: %v", err)
	}

	// Parse PKCS#12
	parsedKey, parsedCert, parsedCAs, err := pkcs12.Parse(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	// Verify parsed content
	if parsedCert == nil {
		t.Fatalf("Certificate not parsed")
	}

	if parsedKey == nil {
		t.Fatalf("Private key not parsed")
	}

	if parsedCert.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Parsed certificate CN mismatch")
	}

	if len(parsedCAs) < 1 {
		t.Errorf("CA certificates not parsed")
	}

	t.Logf("✓ Successfully parsed PKCS#12 bundle with Bao materials")
}

// testPKCS12ExtractReimportBao tests extracting from PKCS#12 and re-importing to Bao.
func testPKCS12ExtractReimportBao(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Create PKCS#12
	password := "test-password"
	pfxData, err := pkcs12.Create(keyPair, certificate, nil, password, pkcs12.Options{
		FriendlyName: "Test Bundle",
	})
	if err != nil {
		t.Fatalf("Failed to create PKCS#12: %v", err)
	}

	// Parse PKCS#12
	parsedKey, parsedCert, _, err := pkcs12.Parse(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	// Convert parsed key to RSAKeyPair (type assertion)
	rsaKey, ok := parsedKey.(*algo.RSAKeyPair)
	if !ok {
		t.Fatalf("Parsed key is not RSAKeyPair")
	}

	// Re-import key to Bao
	reimportedKeyClient, err := env.Client.ImportRSAKey(env.Ctx, "reimported-key", rsaKey, &bao.ImportKeyOptions{})
	if err != nil {
		t.Fatalf("Failed to re-import key to Bao: %v", err)
	}

	// Verify key is accessible
	keyInfo, err := reimportedKeyClient.GetKeyInfo(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to get reimported key info: %v", err)
	}

	t.Logf("Key type: %s", keyInfo.KeyType)
	t.Logf("✓ Successfully extracted from PKCS#12 and re-imported to Bao")

	// Verify certificate matches
	if parsedCert.Certificate.Subject.CommonName != certificate.Certificate.Subject.CommonName {
		t.Errorf("Certificate CN mismatch after PKCS#12 roundtrip")
	}
}

// testBaoIssuePKCS12Export tests the full workflow: Bao issues cert → export to PKCS#12.
func testBaoIssuePKCS12Export(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "web-server-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Get CA cert
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	// Export to PKCS#12
	password := "test-password"
	pfxData, err := pkcs12.Create(keyPair,certificate.Certificate, []*x509.Certificate{caCert}, password, pkcs12.Options{
		FriendlyName: "Bao Web Server Certificate",
	})
	if err != nil {
		t.Fatalf("Failed to create PKCS#12: %v", err)
	}

	// Verify by parsing
	parsedKey, parsedCert, parsedCAs, err := pkcs12.Parse(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	if parsedKey == nil {
		t.Fatalf("Private key not in PKCS#12")
	}

	if parsedCert.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	if len(parsedCAs) < 1 {
		t.Errorf("CA certificate not in PKCS#12")
	}

	t.Logf("✓ Successfully completed Bao issue → PKCS#12 export workflow")
	t.Logf("  Certificate CN: %s", parsedCert.Certificate.Subject.CommonName)
	t.Logf("  CA certificates: %d", len(parsedCAs))
}
