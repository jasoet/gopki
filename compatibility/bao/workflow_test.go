//go:build compatibility

package bao_test

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/jasoet/gopki/bao/pki"
	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestWorkflow_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("Complete_CA_To_Certificate_Workflow", testCompleteCAWorkflow)
	t.Run("Key_Rotation_Workflow", testKeyRotationWorkflow)
	t.Run("Hybrid_GoPKI_Bao_Workflow", testHybridGoPKIBaoWorkflow)
}

// testCompleteCAWorkflow tests the complete workflow from CA creation to certificate issuance
func testCompleteCAWorkflow(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Step 1: Generate Root CA
	t.Log("Step 1: Generating Root CA...")
	caResp, err := env.Client.GenerateRootCA(env.Ctx, &pki.CAOptions{
		Type:          "internal",
		CommonName:    "Test Root CA",
		Organization:  []string{"Test Org"},
		Country:       []string{"US"},
		KeyType:       "rsa",
		KeyBits:       2048,
		IssuerName:    "test-root-ca",
		TTL:           "87600h",
		MaxPathLength: -1,
	})
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}
	t.Logf("✓ Root CA created: %s", caResp.IssuerID)

	// Step 2: Get issuer and verify
	issuer, err := env.Client.GetIssuer(env.Ctx, caResp.IssuerID)
	if err != nil {
		t.Fatalf("Failed to get issuer: %v", err)
	}
	t.Logf("✓ Issuer retrieved: %s", issuer.ID())

	// Step 3: Verify CA certificate with GoPKI
	rootCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}
	if rootCert.Certificate.Subject.CommonName != "Test Root CA" {
		t.Errorf("Expected CN='Test Root CA', got %s", rootCert.Certificate.Subject.CommonName)
	}
	t.Log("✓ CA certificate verified with GoPKI")

	// Step 4: Create a role for certificate issuance
	t.Log("Step 4: Creating role for web servers...")
	_, err = issuer.CreateRole(env.Ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		MaxTTL:          "8760h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
	t.Log("✓ Role created: web-server")

	// Step 5: Generate a key in OpenBao
	t.Log("Step 5: Generating RSA key in OpenBao...")
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &pki.GenerateKeyOptions{
		KeyName: "web-server-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	t.Logf("✓ Key generated: %s", keyClient.KeyInfo().KeyID)

	// Step 6: Issue certificate using the key
	t.Log("Step 6: Issuing certificate with OpenBao-managed key...")
	certClient, err := keyClient.IssueCertificate(env.Ctx, "web-server", &pki.GenerateCertificateOptions{
		CommonName: "app.example.com",
		AltNames:   []string{"www.example.com", "api.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	t.Logf("✓ Certificate issued: %s", certClient.CertificateInfo().SerialNumber)

	// Step 7: Verify certificate properties with GoPKI
	certificate := certClient.Certificate()
	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Expected CN='app.example.com', got %s", certificate.Certificate.Subject.CommonName)
	}
	if len(certificate.Certificate.DNSNames) < 2 {
		t.Errorf("Expected at least 2 DNS names, got %d", len(certificate.Certificate.DNSNames))
	}
	t.Log("✓ Certificate properties verified with GoPKI")

	// Step 8: Verify certificate chain with GoPKI
	err = cert.VerifyCertificate(certificate, rootCert)
	if err != nil {
		t.Errorf("Certificate chain verification failed: %v", err)
	}
	t.Log("✓ Certificate chain verified with GoPKI")

	// Step 9: Test certificate revocation
	t.Log("Step 9: Revoking certificate...")
	err = certClient.Revoke(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to revoke certificate: %v", err)
	}
	t.Log("✓ Certificate revoked")

	t.Log("✓ Complete CA workflow successful!")
}

// testKeyRotationWorkflow tests key rotation with certificate re-issuance
func testKeyRotationWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Setup: Create role
	_, err := issuer.CreateRole(env.Ctx, "rotation-role", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Step 1: Generate first key
	t.Log("Step 1: Generating first key...")
	key1, err := env.Client.GenerateRSAKey(env.Ctx, &pki.GenerateKeyOptions{
		KeyName: "rotation-key-1",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate first key: %v", err)
	}
	t.Logf("✓ First key generated: %s", key1.KeyInfo().KeyID)

	// Step 2: Issue certificate with first key
	t.Log("Step 2: Issuing certificate with first key...")
	cert1, err := key1.IssueCertificate(env.Ctx, "rotation-role", &pki.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate with first key: %v", err)
	}
	serial1 := cert1.CertificateInfo().SerialNumber
	t.Logf("✓ Certificate 1 issued: %s", serial1)

	// Step 3: Generate second key (rotation)
	t.Log("Step 3: Generating second key (rotation)...")
	key2, err := env.Client.GenerateRSAKey(env.Ctx, &pki.GenerateKeyOptions{
		KeyName: "rotation-key-2",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	t.Logf("✓ Second key generated: %s", key2.KeyInfo().KeyID)

	// Step 4: Issue certificate with second key
	t.Log("Step 4: Issuing certificate with second key...")
	cert2, err := key2.IssueCertificate(env.Ctx, "rotation-role", &pki.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate with second key: %v", err)
	}
	serial2 := cert2.CertificateInfo().SerialNumber
	t.Logf("✓ Certificate 2 issued: %s", serial2)

	// Step 5: Verify different serials
	if serial1 == serial2 {
		t.Error("Expected different certificate serials after key rotation")
	}
	t.Log("✓ Certificate serials are different (rotation successful)")

	// Step 6: Revoke old certificate
	t.Log("Step 6: Revoking old certificate...")
	err = cert1.Revoke(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to revoke old certificate: %v", err)
	}
	t.Log("✓ Old certificate revoked")

	// Step 7: Verify new certificate is still valid
	retrieved, err := env.Client.GetCertificate(env.Ctx, serial2)
	if err != nil {
		t.Fatalf("Failed to retrieve new certificate: %v", err)
	}
	if retrieved.Certificate.Subject.CommonName != "app.example.com" {
		t.Error("New certificate was affected by old certificate revocation")
	}
	t.Log("✓ New certificate is still valid")

	t.Log("✓ Key rotation workflow successful!")
}

// testHybridGoPKIBaoWorkflow tests workflows mixing GoPKI-generated keys with Bao-issued certificates
func testHybridGoPKIBaoWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Step 1: Create role
	_, err := issuer.CreateRole(env.Ctx, "hybrid-role", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Step 2: Generate key with GoPKI
	t.Log("Step 2: Generating RSA key with GoPKI...")
	localKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key with GoPKI: %v", err)
	}
	t.Log("✓ Key generated with GoPKI")

	// Step 3: Create CSR with GoPKI
	t.Log("Step 3: Creating CSR with GoPKI...")
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:   "hybrid.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		DNSNames: []string{"hybrid.example.com", "www.hybrid.example.com"},
	}
	csr, err := cert.CreateCSR(localKey, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR with GoPKI: %v", err)
	}
	t.Log("✓ CSR created with GoPKI")

	// Step 4: Sign CSR with Bao
	t.Log("Step 4: Signing CSR with OpenBao...")
	signedCert, err := issuer.SignCSR(env.Ctx, csr, &pki.SignCertificateOptions{
		CommonName: "hybrid.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to sign CSR with Bao: %v", err)
	}
	t.Logf("✓ Certificate signed by OpenBao: %s", signedCert.Certificate.SerialNumber)

	// Step 5: Verify certificate with GoPKI
	rootCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get root certificate: %v", err)
	}

	err = cert.VerifyCertificate(signedCert, rootCert)
	if err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
	t.Log("✓ Certificate verified with GoPKI")

	// Step 6: Import key to Bao
	t.Log("Step 6: Importing GoPKI key to OpenBao...")
	importedKey, err := env.Client.ImportRSAKey(env.Ctx, localKey, &pki.ImportKeyOptions{})
	if err != nil {
		t.Fatalf("Failed to import key to Bao: %v", err)
	}
	t.Logf("✓ Key imported to OpenBao: %s", importedKey.KeyInfo().KeyID)

	// Step 7: Issue another certificate using imported key
	t.Log("Step 7: Issuing certificate with imported key...")
	certClient, err := importedKey.IssueCertificate(env.Ctx, "hybrid-role", &pki.GenerateCertificateOptions{
		CommonName: "app.hybrid.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate with imported key: %v", err)
	}
	t.Logf("✓ Certificate issued with imported key: %s", certClient.CertificateInfo().SerialNumber)

	// Step 8: Verify final certificate
	finalCert := certClient.Certificate()
	err = cert.VerifyCertificate(finalCert, rootCert)
	if err != nil {
		t.Errorf("Final certificate verification failed: %v", err)
	}
	t.Log("✓ Final certificate verified with GoPKI")

	t.Log("✓ Hybrid GoPKI ↔ OpenBao workflow successful!")
}
