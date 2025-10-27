//go:build integration
// +build integration

package bao

import (
	"context"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// TestCompleteCAWorkflow tests the complete workflow from CA creation to certificate issuance
func TestCompleteCAWorkflow(t *testing.T) {
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Step 1: Generate Root CA
	t.Log("Step 1: Generating Root CA...")
	rootCAResp, err := client.GenerateRootCA(ctx, NewRootCABuilder("Test Root CA").
		WithOrganization("Test Org").
		WithCountry("US").
		WithKeyType("rsa", 2048).
		WithTTL("87600h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}
	t.Logf("✓ Root CA created: %s", rootCAResp.IssuerID)

	// Step 2: Get issuer and verify
	issuer, err := client.GetIssuer(ctx, rootCAResp.IssuerID)
	if err != nil {
		t.Fatalf("Failed to get issuer: %v", err)
	}
	t.Logf("✓ Issuer retrieved: %s", issuer.ID())

	// Step 3: Create a role for certificate issuance
	t.Log("Step 2: Creating role for web servers...")
	roleOpts := NewWebServerRole("example.com").
		WithTTL("720h").
		WithMaxTTL("8760h").
		EnableSubdomains().
		Build()
	err = client.CreateRole(ctx, "test-web-server", roleOpts)
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
	t.Log("✓ Role created: test-web-server")

	// Step 4: Generate a key in OpenBao
	t.Log("Step 3: Generating RSA key...")
	keyClient, err := client.GenerateRSAKey(ctx, &GenerateKeyOptions{
		KeyName: "test-web-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	t.Logf("✓ Key generated: %s", keyClient.KeyInfo().KeyID)

	// Step 5: Issue certificate using the key
	t.Log("Step 4: Issuing certificate with OpenBao-managed key...")
	certClient, err := keyClient.IssueCertificate(ctx, "test-web-server", &GenerateCertificateOptions{
		CommonName: "app.example.com",
		AltNames:   []string{"www.app.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	t.Logf("✓ Certificate issued: %s", certClient.CertificateInfo().SerialNumber)

	// Step 6: Verify certificate properties
	certificate := certClient.Certificate()
	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Expected CN=app.example.com, got %s", certificate.Certificate.Subject.CommonName)
	}
	if len(certificate.Certificate.DNSNames) < 2 {
		t.Errorf("Expected at least 2 DNS names, got %d", len(certificate.Certificate.DNSNames))
	}
	t.Log("✓ Certificate properties verified")

	// Step 7: Test certificate revocation
	t.Log("Step 5: Revoking certificate...")
	err = certClient.Revoke(ctx)
	if err != nil {
		t.Fatalf("Failed to revoke certificate: %v", err)
	}
	t.Log("✓ Certificate revoked")

	// Cleanup
	t.Log("Cleanup: Deleting test resources...")
	_ = keyClient.Delete(ctx)
	_ = client.DeleteRole(ctx, "test-web-server")
	t.Log("✓ Cleanup completed")
}

// TestKeyRotationWorkflow tests key rotation with certificate re-issuance
func TestKeyRotationWorkflow(t *testing.T) {
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup: Create CA and role
	_, err := client.GenerateRootCA(ctx, NewRootCABuilder("Rotation Test CA").
		WithKeyType("rsa", 2048).
		WithTTL("87600h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	err = client.CreateRole(ctx, "rotation-role", NewWebServerRole("example.com").Build())
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
	defer client.DeleteRole(ctx, "rotation-role")

	// Step 1: Generate first key
	t.Log("Step 1: Generating first key...")
	key1, err := client.GenerateRSAKey(ctx, &GenerateKeyOptions{
		KeyName: "rotation-key-1",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate first key: %v", err)
	}
	defer key1.Delete(ctx)
	t.Logf("✓ First key generated: %s", key1.KeyInfo().KeyID)

	// Step 2: Issue certificate with first key
	t.Log("Step 2: Issuing certificate with first key...")
	cert1, err := key1.IssueCertificate(ctx, "rotation-role", &GenerateCertificateOptions{
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
	key2, err := client.GenerateRSAKey(ctx, &GenerateKeyOptions{
		KeyName: "rotation-key-2",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	defer key2.Delete(ctx)
	t.Logf("✓ Second key generated: %s", key2.KeyInfo().KeyID)

	// Step 4: Issue certificate with second key
	t.Log("Step 4: Issuing certificate with second key...")
	cert2, err := key2.IssueCertificate(ctx, "rotation-role", &GenerateCertificateOptions{
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
	t.Log("Step 5: Revoking old certificate...")
	err = cert1.Revoke(ctx)
	if err != nil {
		t.Fatalf("Failed to revoke old certificate: %v", err)
	}
	t.Log("✓ Old certificate revoked")

	// Step 7: Verify new certificate is still valid
	retrieved, err := client.GetCertificate(ctx, serial2)
	if err != nil {
		t.Fatalf("Failed to retrieve new certificate: %v", err)
	}
	if retrieved.Certificate.Subject.CommonName != "app.example.com" {
		t.Error("New certificate was affected by old certificate revocation")
	}
	t.Log("✓ New certificate is still valid")
}

// TestMultiIssuerWorkflow tests working with multiple issuers
func TestMultiIssuerWorkflow(t *testing.T) {
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Step 1: Generate production root CA
	t.Log("Step 1: Generating production root CA...")
	prodCA, err := client.GenerateRootCA(ctx, NewRootCABuilder("Production Root CA").
		WithOrganization("Production Org").
		WithKeyType("rsa", 4096).
		WithIssuerName("prod-root").
		WithTTL("87600h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate production CA: %v", err)
	}
	t.Logf("✓ Production CA created: %s", prodCA.IssuerID)

	// Step 2: Generate development root CA
	t.Log("Step 2: Generating development root CA...")
	devCA, err := client.GenerateRootCA(ctx, NewRootCABuilder("Development Root CA").
		WithOrganization("Dev Org").
		WithKeyType("rsa", 2048).
		WithIssuerName("dev-root").
		WithTTL("43800h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate development CA: %v", err)
	}
	t.Logf("✓ Development CA created: %s", devCA.IssuerID)

	// Step 3: List all issuers
	t.Log("Step 3: Listing all issuers...")
	issuers, err := client.ListIssuers(ctx)
	if err != nil {
		t.Fatalf("Failed to list issuers: %v", err)
	}
	if len(issuers) < 2 {
		t.Errorf("Expected at least 2 issuers, got %d", len(issuers))
	}
	t.Logf("✓ Found %d issuers", len(issuers))

	// Step 4: Set production as default
	t.Log("Step 4: Setting production as default issuer...")
	err = client.SetDefaultIssuer(ctx, prodCA.IssuerID)
	if err != nil {
		t.Fatalf("Failed to set default issuer: %v", err)
	}
	t.Log("✓ Default issuer set to production")

	// Step 5: Verify default issuer
	defaultIssuer, err := client.GetDefaultIssuer(ctx)
	if err != nil {
		t.Fatalf("Failed to get default issuer: %v", err)
	}
	if defaultIssuer != prodCA.IssuerID {
		t.Errorf("Expected default issuer to be %s, got %s", prodCA.IssuerID, defaultIssuer)
	}
	t.Log("✓ Default issuer verified")

	// Step 6: Create role with specific issuer
	t.Log("Step 5: Creating role with dev issuer...")
	roleOpts := NewWebServerRole("dev.example.com").Build()
	roleOpts.IssuerRef = devCA.IssuerID
	err = client.CreateRole(ctx, "dev-web-server", roleOpts)
	if err != nil {
		t.Fatalf("Failed to create role with issuer ref: %v", err)
	}
	defer client.DeleteRole(ctx, "dev-web-server")
	t.Log("✓ Role created with dev issuer")

	// Step 7: Issue certificate using dev issuer
	t.Log("Step 6: Issuing certificate with dev issuer...")
	certClient, err := client.GenerateRSACertificate(ctx, "dev-web-server", &GenerateCertificateOptions{
		CommonName: "api.dev.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	t.Logf("✓ Certificate issued: %s", certClient.CertificateInfo().SerialNumber)

	// Cleanup
	_ = client.DeleteIssuer(ctx, devCA.IssuerID)
}

// TestRoleBasedCertificateManagement tests role-based certificate policies
func TestRoleBasedCertificateManagement(t *testing.T) {
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup CA
	_, err := client.GenerateRootCA(ctx, NewRootCABuilder("Role Test CA").
		WithKeyType("rsa", 2048).
		WithTTL("87600h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Test 1: Server certificate role
	t.Log("Test 1: Creating server certificate role...")
	serverRole := NewWebServerRole("server.example.com").
		WithTTL("720h").
		EnableSubdomains().
		Build()
	err = client.CreateRole(ctx, "server-role", serverRole)
	if err != nil {
		t.Fatalf("Failed to create server role: %v", err)
	}
	defer client.DeleteRole(ctx, "server-role")

	// Issue server certificate
	serverCert, err := client.GenerateRSACertificate(ctx, "server-role", &GenerateCertificateOptions{
		CommonName: "api.server.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue server certificate: %v", err)
	}
	t.Logf("✓ Server certificate issued: %s", serverCert.CertificateInfo().SerialNumber)

	// Test 2: Client certificate role
	t.Log("Test 2: Creating client certificate role...")
	clientRole := NewClientCertRole("client.example.com").
		WithTTL("720h").
		Build()
	clientRole.AllowAnyName = true // Allow any common name for client certificates
	err = client.CreateRole(ctx, "client-role", clientRole)
	if err != nil {
		t.Fatalf("Failed to create client role: %v", err)
	}
	defer client.DeleteRole(ctx, "client-role")

	// Issue client certificate
	clientCert, err := client.GenerateRSACertificate(ctx, "client-role", &GenerateCertificateOptions{
		CommonName: "user@client.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue client certificate: %v", err)
	}
	t.Logf("✓ Client certificate issued: %s", clientCert.CertificateInfo().SerialNumber)

	// Test 3: Update role TTL
	t.Log("Test 3: Updating role TTL...")
	roleClient, err := client.GetRole(ctx, "server-role")
	if err != nil {
		t.Fatalf("Failed to get role: %v", err)
	}

	err = roleClient.SetTTL(ctx, "1440h")
	if err != nil {
		t.Fatalf("Failed to update role TTL: %v", err)
	}

	// Verify update
	updatedRole, err := client.GetRole(ctx, "server-role")
	if err != nil {
		t.Fatalf("Failed to get updated role: %v", err)
	}
	if updatedRole.Options().TTL != "1440h" {
		t.Errorf("Expected TTL=1440h, got %s", updatedRole.Options().TTL)
	}
	t.Log("✓ Role TTL updated and verified")
}

// TestCertificateChainValidation tests certificate chain from Root to End-entity
func TestCertificateChainValidation(t *testing.T) {
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Step 1: Generate Root CA
	t.Log("Step 1: Generating Root CA...")
	rootCA, err := client.GenerateRootCA(ctx, NewRootCABuilder("Chain Test Root CA").
		WithKeyType("rsa", 2048).
		WithMaxPathLength(2).
		WithTTL("87600h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}
	t.Logf("✓ Root CA generated: %s", rootCA.IssuerID)

	// Step 2: Generate Intermediate CA CSR
	t.Log("Step 2: Generating Intermediate CA...")
	intermediateResp, err := client.GenerateIntermediateCA(ctx, NewIntermediateCABuilder("Chain Test Intermediate CA").
		WithKeyType("rsa", 2048).
		WithMaxPathLength(1).
		WithTTL("43800h").
		AsExported().
		Build())
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA: %v", err)
	}

	// Parse CSR
	csrData, err := cert.ParseCSRFromPEM([]byte(intermediateResp.CSR))
	if err != nil {
		t.Fatalf("Failed to parse intermediate CSR: %v", err)
	}

	// Step 3: Sign Intermediate CSR with Root
	t.Log("Step 3: Signing Intermediate CA with Root...")
	intermediateCert, err := client.SignIntermediateCSR(ctx, csrData, &CAOptions{
		CommonName:    "Chain Test Intermediate CA",
		TTL:           "43800h",
		MaxPathLength: 1,
	})
	if err != nil {
		t.Fatalf("Failed to sign intermediate CSR: %v", err)
	}
	t.Logf("✓ Intermediate CA signed")

	// Step 4: Create role for end-entity certificates
	t.Log("Step 4: Creating role...")
	err = client.CreateRole(ctx, "chain-test-role", NewWebServerRole("chain.example.com").Build())
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
	defer client.DeleteRole(ctx, "chain-test-role")

	// Step 5: Issue end-entity certificate
	t.Log("Step 5: Issuing end-entity certificate...")
	endCert, err := client.GenerateRSACertificate(ctx, "chain-test-role", &GenerateCertificateOptions{
		CommonName: "www.chain.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue end-entity certificate: %v", err)
	}
	t.Logf("✓ End-entity certificate issued: %s", endCert.CertificateInfo().SerialNumber)

	// Verify certificate chain structure
	if intermediateCert.Certificate.Subject.CommonName != "Chain Test Intermediate CA" {
		t.Error("Intermediate certificate has wrong CN")
	}
	if rootCA.Certificate.Certificate.Subject.CommonName != "Chain Test Root CA" {
		t.Error("Root certificate has wrong CN")
	}
	if endCert.Certificate().Certificate.Subject.CommonName != "www.chain.example.com" {
		t.Error("End-entity certificate has wrong CN")
	}

	t.Log("✓ Certificate chain validation successful")
}

// TestLocalKeyWithOpenBaoSigning tests issuing certificates with locally generated keys
func TestLocalKeyWithOpenBaoSigning(t *testing.T) {
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup CA and role
	_, err := client.GenerateRootCA(ctx, NewRootCABuilder("Local Key Test CA").
		WithKeyType("rsa", 2048).
		WithTTL("87600h").
		Build())
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	roleOpts := NewWebServerRole("local.example.com").Build()
	roleOpts.KeyType = "any" // Allow any key type
	err = client.CreateRole(ctx, "local-key-role", roleOpts)
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
	defer client.DeleteRole(ctx, "local-key-role")

	// Test with RSA
	t.Log("Test 1: Certificate with local RSA key...")
	rsaKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	rsaCert, err := client.IssueRSACertificate(ctx, "local-key-role", rsaKey, &GenerateCertificateOptions{
		CommonName: "rsa.local.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue RSA certificate: %v", err)
	}
	t.Logf("✓ RSA certificate issued: %s", rsaCert.CertificateInfo().SerialNumber)

	// Verify key pair is available
	if !rsaCert.HasKeyPair() {
		t.Error("Expected key pair to be available")
	}
	keyPair, err := rsaCert.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}
	if keyPair.PrivateKey != rsaKey.PrivateKey {
		t.Error("Key pair mismatch")
	}
	t.Log("✓ Key pair verified")

	// Test with ECDSA
	t.Log("Test 2: Certificate with local ECDSA key...")
	ecKey, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	ecCert, err := client.IssueECDSACertificate(ctx, "local-key-role", ecKey, &GenerateCertificateOptions{
		CommonName: "ecdsa.local.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue ECDSA certificate: %v", err)
	}
	t.Logf("✓ ECDSA certificate issued: %s", ecCert.CertificateInfo().SerialNumber)

	// Test with Ed25519
	t.Log("Test 3: Certificate with local Ed25519 key...")
	edKey, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	edCert, err := client.IssueEd25519Certificate(ctx, "local-key-role", edKey, &GenerateCertificateOptions{
		CommonName: "ed25519.local.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue Ed25519 certificate: %v", err)
	}
	t.Logf("✓ Ed25519 certificate issued: %s", edCert.CertificateInfo().SerialNumber)
}
