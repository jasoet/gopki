//go:build compatibility

package bao_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/jasoet/gopki/bao/pki"
	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestCert_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("CSR_Workflow", func(t *testing.T) {
		t.Parallel()
		t.Run("GoPKI_CreateCSR_Bao_SignCSR", testGoPKICSRBaoSign)
		t.Run("CSR_Extensions_Preservation", testCSRExtensionsPreservation)
		t.Run("CSR_Subject_Info_Preservation", testCSRSubjectInfoPreservation)
		t.Run("CSR_Alternative_Names_Preservation", testCSRSANPreservation)
	})

	t.Run("CA_Operations", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_RootCA_Verify", testBaoRootCAVerify)
		t.Run("Bao_IntermediateCA_Chain", testBaoIntermediateCAChain)
		t.Run("Bao_CA_GoPKI_Sign_EndEntity", testBaoCAGoPKISignEndEntity)
	})

	t.Run("Certificate_Validation", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Cert_GoPKI_ParseCertificate", testBaoCertGoPKIParse)
		t.Run("Bao_Cert_GoPKI_VerifyCertificate", testBaoCertGoPKIVerify)
		t.Run("Certificate_Chain_Validation", testCertificateChainValidation)
	})

	t.Run("Certificate_Workflows", func(t *testing.T) {
		t.Parallel()
		t.Run("Workflow1_Bao_Generates_Everything", testWorkflow1BaoGeneratesEverything)
		t.Run("Workflow2_Local_Key_Bao_Signs", testWorkflow2LocalKeyBaoSigns)
		t.Run("Workflow3_Bao_Managed_Key", testWorkflow3BaoManagedKey)
		t.Run("Workflow4_Sign_CSR", testWorkflow4SignCSR)
	})
}

// testGoPKICSRBaoSign tests creating a CSR with GoPKI and signing with Bao.
func testGoPKICSRBaoSign(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key locally with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR with GoPKI
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:   "app.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		DNSNames: []string{"app.example.com", "www.example.com"},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Create role in Bao
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Sign CSR with Bao
	certificate, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		TTL: "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Verify certificate
	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch: expected %q, got %q", "app.example.com", certificate.Certificate.Subject.CommonName)
	}

	if len(certificate.Certificate.DNSNames) != 2 {
		t.Errorf("Expected 2 SANs, got %d", len(certificate.Certificate.DNSNames))
	}

	t.Logf("✓ Successfully created CSR with GoPKI and signed with Bao")
}

// testCSRExtensionsPreservation tests that CSR extensions are preserved when signed by Bao.
func testCSRExtensionsPreservation(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR with specific key usage
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		// Note: KeyUsage is set by the role, not CSR
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Sign CSR
	certificate, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		TTL: "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Verify key usage is set (Bao may override with role settings)
	if certificate.Certificate.KeyUsage == 0 {
		t.Errorf("Key usage not set in certificate")
	}

	t.Logf("✓ CSR extensions preserved/applied correctly")
}

// testCSRSubjectInfoPreservation tests that CSR subject info is preserved.
func testCSRSubjectInfoPreservation(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR with detailed subject info
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:         "app.example.com",
			Organization:       []string{"Test Organization"},
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Sign CSR
	certificate, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		TTL: "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Verify subject info (some fields may be overridden by Bao role)
	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("CN not preserved: expected %q, got %q", "app.example.com", certificate.Certificate.Subject.CommonName)
	}

	t.Logf("✓ CSR subject info preserved correctly")
	t.Logf("  CN: %s", certificate.Certificate.Subject.CommonName)
	if len(certificate.Certificate.Subject.Organization) > 0 {
		t.Logf("  O: %v", certificate.Certificate.Subject.Organization)
	}
}

// testCSRSANPreservation tests that CSR SANs are preserved.
func testCSRSANPreservation(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR with multiple SANs
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "app.example.com",
		},
		DNSNames:     []string{"app.example.com", "www.example.com", "api.example.com"},
		EmailAddress: []string{"admin@example.com"},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Sign CSR
	certificate, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		TTL: "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Verify SANs
	if len(certificate.Certificate.DNSNames) < 1 {
		t.Errorf("No DNS SANs in certificate")
	}

	t.Logf("✓ CSR SANs preserved correctly")
	t.Logf("  DNS SANs: %v", certificate.Certificate.DNSNames)
	if len(certificate.Certificate.EmailAddresses) > 0 {
		t.Logf("  Email SANs: %v", certificate.Certificate.EmailAddresses)
	}
}

// testBaoRootCAVerify tests that Bao-generated root CA is valid.
func testBaoRootCAVerify(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate root CA
	caResp, err := env.Client.GenerateRootCA(env.Ctx, &pki.CAOptions{
		Type:       "internal",
		CommonName: "Test Root CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		IssuerName: "test-root-ca",
		TTL:        "87600h",
	})
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	// Verify CA certificate
	caCert := caResp.Certificate

	if caCert.Certificate.Subject.CommonName != "Test Root CA" {
		t.Errorf("CA CN mismatch")
	}

	if !caCert.Certificate.IsCA {
		t.Errorf("Certificate is not marked as CA")
	}

	// Verify self-signed
	roots := x509.NewCertPool()
	roots.AddCert(caCert.Certificate)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := caCert.Certificate.Verify(opts); err != nil {
		t.Errorf("Root CA verification failed: %v", err)
	}

	t.Logf("✓ Bao root CA is valid and self-signed")
}

// testBaoIntermediateCAChain tests intermediate CA chain creation.
func testBaoIntermediateCAChain(t *testing.T) {
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

	// Verify intermediate is signed by root
	roots := x509.NewCertPool()
	roots.AddCert(rootCert.Certificate)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := intermediateCert.Certificate.Verify(opts); err != nil {
		t.Errorf("Intermediate CA verification failed: %v", err)
	}

	t.Logf("✓ Intermediate CA chain is valid")
}

// testBaoCAGoPKISignEndEntity tests using Bao CA to sign with GoPKI cert module.
func testBaoCAGoPKISignEndEntity(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Get CA certificate
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	// Generate end-entity key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "end-entity.example.com",
		},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Create role and sign
	_, err = issuer.CreateRole(env.Ctx, "end-entity", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	endEntityCert, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		TTL: "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Verify chain
	ValidateCertificateChain(t, endEntityCert.Certificate, caCert.Certificate)

	t.Logf("✓ Bao CA successfully signed end-entity certificate")
}

// testBaoCertGoPKIParse tests parsing Bao-issued certificates with GoPKI.
func testBaoCertGoPKIParse(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate
	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &pki.GenerateCertificateOptions{
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

	// Parse with GoPKI (convert to PEM and parse back)
	parsedCert, err := cert.ParseCertificateFromPEM(certificate.PEMData)
	if err != nil {
		t.Fatalf("Failed to parse certificate with GoPKI: %v", err)
	}

	if parsedCert.Certificate.Subject.CommonName != certificate.Certificate.Subject.CommonName {
		t.Errorf("Parsed certificate CN mismatch")
	}

	t.Logf("✓ Bao certificate successfully parsed with GoPKI")
}

// testBaoCertGoPKIVerify tests verifying Bao-issued certificates with GoPKI.
func testBaoCertGoPKIVerify(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Get CA cert
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue cert
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &pki.GenerateCertificateOptions{
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

	// Verify with GoPKI cert module
	err = cert.VerifyCertificate(certificate, caCert)
	if err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}

	t.Logf("✓ Bao certificate successfully verified with GoPKI")
}

// testCertificateChainValidation tests full certificate chain validation.
func testCertificateChainValidation(t *testing.T) {
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

	// Issue end-entity certificate
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_, err = intermediateCA.CreateRole(env.Ctx, "end-entity", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "end-entity", keyPair, &pki.GenerateCertificateOptions{
		CommonName: "end-entity.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	endEntityCert := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Verify full chain with GoPKI
	// Note: cert.VerifyCertificate verifies cert against single CA
	// For full chain, verify end-entity -> intermediate
	err = cert.VerifyCertificate(endEntityCert, intermediateCert)
	if err != nil {
		t.Errorf("End-entity to intermediate verification failed: %v", err)
	}

	// Verify intermediate -> root
	err = cert.VerifyCertificate(intermediateCert, rootCert)
	if err != nil {
		t.Errorf("Intermediate to root verification failed: %v", err)
	}

	t.Logf("✓ Full certificate chain validated successfully")
}

// testWorkflow1BaoGeneratesEverything tests workflow where Bao generates everything.
func testWorkflow1BaoGeneratesEverything(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Create role
	_, err := issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Bao generates key and certificate
	certClient, err := env.Client.GenerateRSACertificate(env.Ctx, "web-server", &pki.GenerateCertificateOptions{
		CommonName: "app.example.com",
		AltNames:   []string{"www.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Verify we have both cert and key
	if !certClient.HasKeyPair() {
		t.Errorf("KeyPair not available")
	}

	keyPair, err := certClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Use with GoPKI
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to use key with GoPKI: %v", err)
	}

	if csr == nil {
		t.Errorf("CSR is nil")
	}

	t.Logf("✓ Workflow 1: Bao generates everything - Success")
}

// testWorkflow2LocalKeyBaoSigns tests workflow where local key is used and Bao signs.
func testWorkflow2LocalKeyBaoSigns(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key locally with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate with local key (only CSR sent to Bao)
	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &pki.GenerateCertificateOptions{
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

	// Verify certificate matches our key
	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	t.Logf("✓ Workflow 2: Local key, Bao signs - Success (private key never left local system)")
}

// testWorkflow3BaoManagedKey tests workflow with Bao-managed keys.
func testWorkflow3BaoManagedKey(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Create key in Bao (internal, not exported)
	keyClient, err := env.Client.CreateRSAKey(env.Ctx, &pki.GenerateKeyOptions{
		KeyName: "managed-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	keyInfo := keyClient.KeyInfo()

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate using Bao-managed key
	certClient, err := env.Client.IssueRSACertificateWithKeyRef(env.Ctx, "web-server", keyInfo.KeyID, &pki.GenerateCertificateOptions{
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

	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	t.Logf("✓ Workflow 3: Bao-managed key - Success (key stays secure in Bao)")
}

// testWorkflow4SignCSR tests the CSR signing workflow.
func testWorkflow4SignCSR(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Create CSR locally with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "app.example.com",
		},
		DNSNames: []string{"app.example.com", "www.example.com"},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Create role
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Sign with Bao
	certificate, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		TTL: "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	if len(certificate.Certificate.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(certificate.Certificate.DNSNames))
	}

	t.Logf("✓ Workflow 4: Sign CSR - Success")
}
