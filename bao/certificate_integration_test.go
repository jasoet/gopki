//go:build integration

package bao

import (
	"context"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// Integration Tests for Certificate Operations
// ============================================================================

func TestIntegration_CertificateGeneration(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("Generate RSA certificate", func(t *testing.T) {
		certClient, err := client.GenerateRSACertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "rsa-test.example.com",
			AltNames:   []string{"www.rsa-test.example.com"},
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("GenerateRSACertificate failed: %v", err)
		}

		// Verify certificate
		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if cert.Certificate == nil {
			t.Fatal("Expected x509 certificate, got nil")
		}
		if cert.Certificate.Subject.CommonName != "rsa-test.example.com" {
			t.Errorf("Expected CN 'rsa-test.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}

		// Verify key pair is available
		if !certClient.HasKeyPair() {
			t.Error("Expected key pair to be available")
		}

		keyPair, err := certClient.KeyPair()
		if err != nil {
			t.Errorf("KeyPair() failed: %v", err)
		}
		if keyPair == nil {
			t.Error("Expected key pair, got nil")
		}
	})

	t.Run("Generate ECDSA certificate", func(t *testing.T) {
		certClient, err := client.GenerateECDSACertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "ecdsa-test.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("GenerateECDSACertificate failed: %v", err)
		}

		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if !certClient.HasKeyPair() {
			t.Error("Expected key pair to be available")
		}
	})

	t.Run("Generate Ed25519 certificate", func(t *testing.T) {
		certClient, err := client.GenerateEd25519Certificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "ed25519-test.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("GenerateEd25519Certificate failed: %v", err)
		}

		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if !certClient.HasKeyPair() {
			t.Error("Expected key pair to be available")
		}
	})
}

func TestIntegration_CertificateIssuance(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("Issue RSA certificate with local key", func(t *testing.T) {
		// Generate local key pair
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Issue certificate
		certClient, err := client.IssueRSACertificate(ctx, "test-role", keyPair, &GenerateCertificateOptions{
			CommonName: "local-rsa.example.com",
			AltNames:   []string{"www.local-rsa.example.com", "api.local-rsa.example.com"},
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("IssueRSACertificate failed: %v", err)
		}

		// Verify certificate
		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if cert.Certificate.Subject.CommonName != "local-rsa.example.com" {
			t.Errorf("Expected CN 'local-rsa.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}

		// Verify key pair is available (local key)
		if !certClient.HasKeyPair() {
			t.Error("Expected key pair to be available")
		}

		cachedKeyPair, err := certClient.KeyPair()
		if err != nil {
			t.Fatalf("KeyPair() failed: %v", err)
		}
		if cachedKeyPair.PrivateKey != keyPair.PrivateKey {
			t.Error("Expected cached key pair to match original")
		}
	})

	t.Run("Issue ECDSA certificate with local key", func(t *testing.T) {
		keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		certClient, err := client.IssueECDSACertificate(ctx, "test-role", keyPair, &GenerateCertificateOptions{
			CommonName: "local-ecdsa.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("IssueECDSACertificate failed: %v", err)
		}

		if !certClient.HasKeyPair() {
			t.Error("Expected key pair to be available")
		}
	})

	t.Run("Issue Ed25519 certificate with local key", func(t *testing.T) {
		keyPair, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		certClient, err := client.IssueEd25519Certificate(ctx, "test-role", keyPair, &GenerateCertificateOptions{
			CommonName: "local-ed25519.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("IssueEd25519Certificate failed: %v", err)
		}

		if !certClient.HasKeyPair() {
			t.Error("Expected key pair to be available")
		}
	})
}

func TestIntegration_CertificateWithKeyRef(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("Issue RSA certificate with OpenBao key reference", func(t *testing.T) {
		// Create key in OpenBao
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "test-rsa-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create RSA key: %v", err)
		}

		keyRef := keyClient.KeyInfo().KeyID

		// Issue certificate using key reference
		certClient, err := client.IssueRSACertificateWithKeyRef(ctx, "test-role", keyRef, &GenerateCertificateOptions{
			CommonName: "keyref-rsa.example.com",
			AltNames:   []string{"www.keyref-rsa.example.com"},
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("IssueRSACertificateWithKeyRef failed: %v", err)
		}

		// Verify certificate
		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if cert.Certificate.Subject.CommonName != "keyref-rsa.example.com" {
			t.Errorf("Expected CN 'keyref-rsa.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}

		// Verify key pair is NOT available (key stays in OpenBao)
		if certClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available (key in OpenBao)")
		}

		_, err = certClient.KeyPair()
		if err == nil {
			t.Error("Expected error when getting key pair (key not cached)")
		}
	})

	t.Run("Issue ECDSA certificate with OpenBao key reference", func(t *testing.T) {
		keyClient, err := client.CreateECDSAKey(ctx, &GenerateKeyOptions{
			KeyName: "test-ec-key",
			KeyBits: 256,
		})
		if err != nil {
			t.Fatalf("Failed to create ECDSA key: %v", err)
		}

		keyRef := keyClient.KeyInfo().KeyID

		certClient, err := client.IssueECDSACertificateWithKeyRef(ctx, "test-role", keyRef, &GenerateCertificateOptions{
			CommonName: "keyref-ecdsa.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("IssueECDSACertificateWithKeyRef failed: %v", err)
		}

		if certClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available (key in OpenBao)")
		}
	})

	t.Run("Issue Ed25519 certificate with OpenBao key reference", func(t *testing.T) {
		keyClient, err := client.CreateEd25519Key(ctx, &GenerateKeyOptions{
			KeyName: "test-ed25519-key",
		})
		if err != nil {
			t.Fatalf("Failed to create Ed25519 key: %v", err)
		}

		keyRef := keyClient.KeyInfo().KeyID

		certClient, err := client.IssueEd25519CertificateWithKeyRef(ctx, "test-role", keyRef, &GenerateCertificateOptions{
			CommonName: "keyref-ed25519.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("IssueEd25519CertificateWithKeyRef failed: %v", err)
		}

		if certClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available (key in OpenBao)")
		}
	})
}

func TestIntegration_KeyClientConvenience(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("KeyClient.IssueCertificate convenience method", func(t *testing.T) {
		// Create key in OpenBao
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "convenience-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}

		// Issue certificate directly from KeyClient
		certClient, err := keyClient.IssueCertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "convenience.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("KeyClient.IssueCertificate failed: %v", err)
		}

		// Verify certificate
		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if cert.Certificate.Subject.CommonName != "convenience.example.com" {
			t.Errorf("Expected CN 'convenience.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}
	})

	t.Run("KeyClient.SignCSR convenience method", func(t *testing.T) {
		// Create key in OpenBao
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "signing-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}

		// Create local key pair and CSR
		localKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate local key: %v", err)
		}

		csr, err := cert.CreateCSR(localKeyPair, cert.CSRRequest{
			Subject: pkix.Name{
				CommonName: "csr-test.example.com",
			},
			DNSNames: []string{"csr-test.example.com", "www.csr-test.example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		// Sign CSR using KeyClient convenience method
		certificate, err := keyClient.SignCSR(ctx, "test-role", csr, &SignCertificateOptions{
			TTL: "1h",
		})
		if err != nil {
			t.Fatalf("KeyClient.SignCSR failed: %v", err)
		}

		if certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if certificate.Certificate.Subject.CommonName != "csr-test.example.com" {
			t.Errorf("Expected CN 'csr-test.example.com', got '%s'", certificate.Certificate.Subject.CommonName)
		}
	})
}

func TestIntegration_CertificateRetrieval(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("Get RSA certificate", func(t *testing.T) {
		// Generate certificate first
		certClient, err := client.GenerateRSACertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "retrieve-rsa.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		serial := certClient.CertificateInfo().SerialNumber
		if serial == "" {
			t.Fatal("Expected serial number, got empty string")
		}

		// Retrieve certificate
		retrievedClient, err := client.GetRSACertificate(ctx, serial)
		if err != nil {
			t.Fatalf("GetRSACertificate failed: %v", err)
		}

		if retrievedClient == nil {
			t.Fatal("Expected certificate client, got nil")
		}

		// Verify certificate
		cert := retrievedClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if cert.Certificate.Subject.CommonName != "retrieve-rsa.example.com" {
			t.Errorf("Expected CN 'retrieve-rsa.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}

		// Verify key pair NOT available (only retrieval)
		if retrievedClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available (retrieval only)")
		}
	})

	t.Run("List certificates", func(t *testing.T) {
		// Generate a few certificates
		for i := 0; i < 3; i++ {
			_, err := client.GenerateRSACertificate(ctx, "test-role", &GenerateCertificateOptions{
				CommonName: "list-test-" + string(rune('a'+i)) + ".example.com",
				TTL:        "1h",
			})
			if err != nil {
				t.Fatalf("Failed to generate certificate: %v", err)
			}
		}

		// List certificates
		serials, err := client.ListCertificates(ctx)
		if err != nil {
			t.Fatalf("ListCertificates failed: %v", err)
		}

		if len(serials) < 3 {
			t.Errorf("Expected at least 3 certificates, got %d", len(serials))
		}
	})
}

func TestIntegration_CertificateRevocation(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("Revoke certificate by serial", func(t *testing.T) {
		// Generate certificate
		certClient, err := client.GenerateRSACertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "revoke-test.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Revoke using CertificateClient.Revoke()
		err = certClient.Revoke(ctx)
		if err != nil {
			t.Fatalf("Revoke failed: %v", err)
		}
	})

	t.Run("Revoke certificate using serial directly", func(t *testing.T) {
		// Generate certificate
		certClient, err := client.GenerateRSACertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "revoke-direct.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		serial := certClient.CertificateInfo().SerialNumber

		// Revoke using Client.RevokeCertificate()
		err = client.RevokeCertificate(ctx, serial)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})
}

func TestIntegration_SignCSR(t *testing.T) {
	ctx := context.Background()

	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Setup root CA and role
	setupRootCAAndRole(t, ctx, client)

	t.Run("Sign CSR", func(t *testing.T) {
		// Create local key pair and CSR
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		csr, err := cert.CreateCSR(keyPair, cert.CSRRequest{
			Subject: pkix.Name{
				CommonName: "sign-csr.example.com",
			},
			DNSNames: []string{"sign-csr.example.com", "www.sign-csr.example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		// Sign CSR
		certificate, err := client.SignCSR(ctx, "test-role", csr, &SignCertificateOptions{
			TTL: "1h",
		})
		if err != nil {
			t.Fatalf("SignCSR failed: %v", err)
		}

		if certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if certificate.Certificate.Subject.CommonName != "sign-csr.example.com" {
			t.Errorf("Expected CN 'sign-csr.example.com', got '%s'", certificate.Certificate.Subject.CommonName)
		}
	})

	t.Run("Sign CSR with key reference", func(t *testing.T) {
		// Create key in OpenBao
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "csr-signing-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}

		// Create local key pair and CSR
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		csr, err := cert.CreateCSR(keyPair, cert.CSRRequest{
			Subject: pkix.Name{
				CommonName: "sign-csr-keyref.example.com",
			},
		})
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		// Sign CSR with key reference
		keyRef := keyClient.KeyInfo().KeyID
		certificate, err := client.SignCSRWithKeyRef(ctx, "test-role", csr, keyRef, &SignCertificateOptions{
			TTL: "1h",
		})
		if err != nil {
			t.Fatalf("SignCSRWithKeyRef failed: %v", err)
		}

		if certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if certificate.Certificate.Subject.CommonName != "sign-csr-keyref.example.com" {
			t.Errorf("Expected CN 'sign-csr-keyref.example.com', got '%s'", certificate.Certificate.Subject.CommonName)
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// setupRootCAAndRole sets up a root CA and test role for certificate operations
func setupRootCAAndRole(t *testing.T, ctx context.Context, client *Client) {
	t.Helper()

	// Generate root CA
	rootData := map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "87600h", // 10 years
	}

	_, err := client.client.Logical().WriteWithContext(ctx, "pki/root/generate/internal", rootData)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Create test role
	roleData := map[string]interface{}{
		"allowed_domains":    []string{"example.com"},
		"allow_subdomains":   true,
		"allow_bare_domains": true,
		"allow_localhost":    true,
		"max_ttl":            "720h",
		"key_type":           "any",
	}

	_, err = client.client.Logical().WriteWithContext(ctx, "pki/roles/test-role", roleData)
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
}
