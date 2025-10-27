//go:build integration

package bao

import (
	"context"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// Integration Tests for Type-Safe Generic API (New)
// ============================================================================

func TestIntegration_TypeSafeGeneration(t *testing.T) {
	ctx := context.Background()

	// Setup container
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

	t.Run("Generate RSA key - type safe", func(t *testing.T) {
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "typesafe-rsa-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateRSAKey failed: %v", err)
		}

		// Verify keyInfo
		keyInfo := keyClient.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyID == "" {
			t.Error("Expected non-empty key ID")
		}
		if keyInfo.KeyName != "typesafe-rsa-key" {
			t.Errorf("Expected key name 'typesafe-rsa-key', got '%s'", keyInfo.KeyName)
		}
		if keyInfo.KeyType != "rsa" {
			t.Errorf("Expected key type 'rsa', got '%s'", keyInfo.KeyType)
		}
	})

	t.Run("Generate ECDSA key - type safe", func(t *testing.T) {
		keyClient, err := client.CreateECDSAKey(ctx, &GenerateKeyOptions{
			KeyName: "typesafe-ec-key",
			KeyBits: 256,
		})
		if err != nil {
			t.Fatalf("GenerateECDSAKey failed: %v", err)
		}

		keyInfo := keyClient.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyType != "ec" {
			t.Errorf("Expected key type 'ec', got '%s'", keyInfo.KeyType)
		}
	})

	t.Run("Generate Ed25519 key - type safe", func(t *testing.T) {
		keyClient, err := client.CreateEd25519Key(ctx, &GenerateKeyOptions{
			KeyName: "typesafe-ed25519-key",
		})
		if err != nil {
			t.Fatalf("GenerateEd25519Key failed: %v", err)
		}

		keyInfo := keyClient.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyType != "ed25519" {
			t.Errorf("Expected key type 'ed25519', got '%s'", keyInfo.KeyType)
		}
	})
}

func TestIntegration_TypeSafeImport(t *testing.T) {
	ctx := context.Background()

	// Setup container
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

	t.Run("Import RSA key - type safe", func(t *testing.T) {
		// Generate local key pair
		localKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair failed: %v", err)
		}

		// Import using type-safe API
		keyClient, err := client.ImportRSAKey(ctx, localKeyPair, &ImportKeyOptions{
			KeyName: "typesafe-imported-rsa",
		})
		if err != nil {
			t.Fatalf("ImportRSAKey failed: %v", err)
		}

		keyInfo := keyClient.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyType != "rsa" {
			t.Errorf("Expected key type 'rsa', got '%s'", keyInfo.KeyType)
		}
		if keyInfo.KeyBits != 2048 {
			t.Errorf("Expected 2048 bits, got %d", keyInfo.KeyBits)
		}
	})

	t.Run("Import ECDSA key - type safe", func(t *testing.T) {
		localKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("GenerateECDSAKeyPair failed: %v", err)
		}

		keyClient, err := client.ImportECDSAKey(ctx, localKeyPair, &ImportKeyOptions{
			KeyName: "typesafe-imported-ec",
		})
		if err != nil {
			t.Fatalf("ImportECDSAKey failed: %v", err)
		}

		keyInfo := keyClient.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyType != "ec" {
			t.Errorf("Expected key type 'ec', got '%s'", keyInfo.KeyType)
		}
		if keyInfo.KeyBits != 256 {
			t.Errorf("Expected 256 bits, got %d", keyInfo.KeyBits)
		}
	})

	t.Run("Import Ed25519 key - type safe", func(t *testing.T) {
		localKeyPair, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
		}

		keyClient, err := client.ImportEd25519Key(ctx, localKeyPair, &ImportKeyOptions{
			KeyName: "typesafe-imported-ed25519",
		})
		if err != nil {
			t.Fatalf("ImportEd25519Key failed: %v", err)
		}

		keyInfo := keyClient.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyType != "ed25519" {
			t.Errorf("Expected key type 'ed25519', got '%s'", keyInfo.KeyType)
		}
	})
}

func TestIntegration_TypeSafeGet(t *testing.T) {
	ctx := context.Background()

	// Setup container
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

	t.Run("Get RSA key by ID - type safe", func(t *testing.T) {
		// First generate a key
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "get-rsa-test",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateRSAKey failed: %v", err)
		}

		// Get the key using type-safe API
		retrievedKey, err := client.GetRSAKey(ctx, keyClient.KeyInfo().KeyID)
		if err != nil {
			t.Fatalf("GetRSAKey failed: %v", err)
		}

		keyInfo := retrievedKey.KeyInfo()
		if keyInfo == nil {
			t.Fatal("Expected key info, got nil")
		}
		if keyInfo.KeyID != keyClient.KeyInfo().KeyID {
			t.Errorf("Key ID mismatch: expected %s, got %s", keyClient.KeyInfo().KeyID, keyInfo.KeyID)
		}
		if keyInfo.KeyType != "rsa" {
			t.Errorf("Expected key type 'rsa', got '%s'", keyInfo.KeyType)
		}
	})

	t.Run("Get ECDSA key by name - type safe", func(t *testing.T) {
		_, err := client.CreateECDSAKey(ctx, &GenerateKeyOptions{
			KeyName: "get-ec-test",
			KeyBits: 256,
		})
		if err != nil {
			t.Fatalf("GenerateECDSAKey failed: %v", err)
		}

		// Get by name
		retrievedKey, err := client.GetECDSAKey(ctx, "get-ec-test")
		if err != nil {
			t.Fatalf("GetECDSAKey failed: %v", err)
		}

		keyInfo := retrievedKey.KeyInfo()
		if keyInfo.KeyName != "get-ec-test" {
			t.Errorf("Key name mismatch: expected 'get-ec-test', got '%s'", keyInfo.KeyName)
		}
	})

	t.Run("Get Ed25519 key - type safe", func(t *testing.T) {
		keyClient, err := client.CreateEd25519Key(ctx, &GenerateKeyOptions{
			KeyName: "get-ed25519-test",
		})
		if err != nil {
			t.Fatalf("GenerateEd25519Key failed: %v", err)
		}

		retrievedKey, err := client.GetEd25519Key(ctx, keyClient.KeyInfo().KeyID)
		if err != nil {
			t.Fatalf("GetEd25519Key failed: %v", err)
		}

		keyInfo := retrievedKey.KeyInfo()
		if keyInfo.KeyType != "ed25519" {
			t.Errorf("Expected key type 'ed25519', got '%s'", keyInfo.KeyType)
		}
	})

	t.Run("Type mismatch error", func(t *testing.T) {
		// Generate an RSA key
		rsaKey, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "rsa-mismatch-test",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateRSAKey failed: %v", err)
		}

		// Try to get it as ECDSA - should fail
		_, err = client.GetECDSAKey(ctx, rsaKey.KeyInfo().KeyID)
		if err == nil {
			t.Error("Expected type mismatch error, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "key type mismatch") {
			t.Errorf("Expected 'key type mismatch' error, got: %v", err)
		}
	})
}

func TestIntegration_KeyClient_Export(t *testing.T) {
	t.Skip("OpenBao PKI does not support key export endpoint - keys can only be exported at generation time with type='exported'")

	// NOTE: OpenBao PKI secrets engine does NOT provide a /key/:id/export endpoint.
	// According to OpenBao documentation (https://openbao.org/api-docs/secret/pki/):
	// - Keys can only be exported at GENERATION time using type="exported"
	// - Once a key is created as "internal", it cannot be retrieved later
	// - Imported keys also cannot be exported after import
	//
	// The Export() method is designed for future compatibility or third-party
	// OpenBao extensions that may provide this functionality.
	//
	// For now, Export() is tested in unit tests with mocked responses.
}

func TestIntegration_KeyClient_Delete(t *testing.T) {
	ctx := context.Background()

	// Setup container
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

	t.Run("Delete key via KeyClient", func(t *testing.T) {
		// Generate a key
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "delete-test-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateRSAKey failed: %v", err)
		}

		keyID := keyClient.KeyInfo().KeyID

		// Delete using KeyClient method
		err = keyClient.Delete(ctx)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Verify deletion - should fail to get
		_, err = client.GetKey(ctx, keyID)
		if err == nil {
			t.Error("Expected error when getting deleted key, got nil")
		}
	})
}

func TestIntegration_KeyClient_UpdateName(t *testing.T) {
	ctx := context.Background()

	// Setup container
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

	t.Run("Update name via KeyClient", func(t *testing.T) {
		// Generate a key
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "original-name",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateRSAKey failed: %v", err)
		}

		// Update name using KeyClient method
		err = keyClient.UpdateName(ctx, "updated-name")
		if err != nil {
			t.Fatalf("UpdateName failed: %v", err)
		}

		// Verify the cached keyInfo was updated
		if keyClient.KeyInfo().KeyName != "updated-name" {
			t.Errorf("Expected cached name 'updated-name', got '%s'", keyClient.KeyInfo().KeyName)
		}

		// Verify via API
		updatedKey, err := client.GetKey(ctx, keyClient.KeyInfo().KeyID)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}
		if updatedKey.KeyName != "updated-name" {
			t.Errorf("Expected server name 'updated-name', got '%s'", updatedKey.KeyName)
		}
	})
}

func TestIntegration_TypeSafeFullWorkflow(t *testing.T) {
	ctx := context.Background()

	// Setup container
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

	t.Run("Complete workflow with type-safe API", func(t *testing.T) {
		// 1. Generate an exportable key
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "workflow-test-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateRSAKey failed: %v", err)
		}

		// 2. Verify KeyInfo
		if keyClient.KeyInfo().KeyName != "workflow-test-key" {
			t.Errorf("Expected name 'workflow-test-key', got '%s'", keyClient.KeyInfo().KeyName)
		}

		// 3. Update name
		err = keyClient.UpdateName(ctx, "workflow-renamed-key")
		if err != nil {
			t.Fatalf("UpdateName failed: %v", err)
		}

		// 4. Get the key again by ID
		retrievedKey, err := client.GetRSAKey(ctx, keyClient.KeyInfo().KeyID)
		if err != nil {
			t.Fatalf("GetRSAKey failed: %v", err)
		}
		if retrievedKey.KeyInfo().KeyName != "workflow-renamed-key" {
			t.Errorf("Expected name 'workflow-renamed-key', got '%s'", retrievedKey.KeyInfo().KeyName)
		}

		// 5. Export the key (not supported by OpenBao PKI)
		// OpenBao PKI does not provide a /key/:id/export endpoint
		// Keys can only be exported at generation time with type="exported"
		// See TestIntegration_KeyClient_Export for details

		// 6. Delete the key
		err = retrievedKey.Delete(ctx)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// 7. Verify deletion
		_, err = client.GetRSAKey(ctx, keyClient.KeyInfo().KeyID)
		if err == nil {
			t.Error("Expected error when getting deleted key, got nil")
		}
	})
}

// ============================================================================
// Integration Tests for KeyClient Certificate Convenience Methods (Phase 2C)
// ============================================================================

func TestIntegration_KeyClient_IssueCertificate(t *testing.T) {
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
	setupRootCAAndRoleForKeyTests(t, ctx, client)

	t.Run("RSA KeyClient.IssueCertificate", func(t *testing.T) {
		// Create RSA key
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "cert-rsa-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create RSA key: %v", err)
		}

		// Issue certificate directly from KeyClient
		certClient, err := keyClient.IssueCertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "keyclient-rsa.example.com",
			AltNames:   []string{"www.keyclient-rsa.example.com"},
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
		if cert.Certificate.Subject.CommonName != "keyclient-rsa.example.com" {
			t.Errorf("Expected CN 'keyclient-rsa.example.com', got '%s'", cert.Certificate.Subject.CommonName)
		}

		// Verify key pair NOT available (key stays in OpenBao)
		if certClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available (key in OpenBao)")
		}
	})

	t.Run("ECDSA KeyClient.IssueCertificate", func(t *testing.T) {
		keyClient, err := client.CreateECDSAKey(ctx, &GenerateKeyOptions{
			KeyName: "cert-ec-key",
			KeyBits: 256,
		})
		if err != nil {
			t.Fatalf("Failed to create ECDSA key: %v", err)
		}

		certClient, err := keyClient.IssueCertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "keyclient-ecdsa.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("KeyClient.IssueCertificate failed: %v", err)
		}

		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}

		if certClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available")
		}
	})

	t.Run("Ed25519 KeyClient.IssueCertificate", func(t *testing.T) {
		keyClient, err := client.CreateEd25519Key(ctx, &GenerateKeyOptions{
			KeyName: "cert-ed25519-key",
		})
		if err != nil {
			t.Fatalf("Failed to create Ed25519 key: %v", err)
		}

		certClient, err := keyClient.IssueCertificate(ctx, "test-role", &GenerateCertificateOptions{
			CommonName: "keyclient-ed25519.example.com",
			TTL:        "1h",
		})
		if err != nil {
			t.Fatalf("KeyClient.IssueCertificate failed: %v", err)
		}

		cert := certClient.Certificate()
		if cert == nil {
			t.Fatal("Expected certificate, got nil")
		}

		if certClient.HasKeyPair() {
			t.Error("Expected key pair to NOT be available")
		}
	})
}

func TestIntegration_KeyClient_SignCSR(t *testing.T) {
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
	setupRootCAAndRoleForKeyTests(t, ctx, client)

	t.Run("RSA KeyClient.SignCSR", func(t *testing.T) {
		// Create signing key in OpenBao
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "signing-rsa-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create RSA key: %v", err)
		}

		// Create local key pair and CSR
		localKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate local key: %v", err)
		}

		csr, err := cert.CreateCSR(localKeyPair, cert.CSRRequest{
			Subject: pkix.Name{
				CommonName: "keyclient-signcsr-rsa.example.com",
			},
			DNSNames: []string{"keyclient-signcsr-rsa.example.com", "www.keyclient-signcsr-rsa.example.com"},
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
		if certificate.Certificate.Subject.CommonName != "keyclient-signcsr-rsa.example.com" {
			t.Errorf("Expected CN 'keyclient-signcsr-rsa.example.com', got '%s'", certificate.Certificate.Subject.CommonName)
		}
	})

	t.Run("ECDSA KeyClient.SignCSR", func(t *testing.T) {
		keyClient, err := client.CreateECDSAKey(ctx, &GenerateKeyOptions{
			KeyName: "signing-ec-key",
			KeyBits: 256,
		})
		if err != nil {
			t.Fatalf("Failed to create ECDSA key: %v", err)
		}

		localKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate local key: %v", err)
		}

		csr, err := cert.CreateCSR(localKeyPair, cert.CSRRequest{
			Subject: pkix.Name{
				CommonName: "keyclient-signcsr-ecdsa.example.com",
			},
		})
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		certificate, err := keyClient.SignCSR(ctx, "test-role", csr, &SignCertificateOptions{
			TTL: "1h",
		})
		if err != nil {
			t.Fatalf("KeyClient.SignCSR failed: %v", err)
		}

		if certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
	})
}

func TestIntegration_KeyClient_SignVerbatim(t *testing.T) {
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
	setupRootCAAndRoleForKeyTests(t, ctx, client)

	t.Run("RSA KeyClient.SignVerbatim", func(t *testing.T) {
		// Create signing key in OpenBao
		keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{
			KeyName: "verbatim-rsa-key",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to create RSA key: %v", err)
		}

		// Create local key pair and CSR
		localKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate local key: %v", err)
		}

		csr, err := cert.CreateCSR(localKeyPair, cert.CSRRequest{
			Subject: pkix.Name{
				CommonName: "keyclient-verbatim.example.com",
			},
		})
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		// Sign CSR verbatim using KeyClient convenience method
		certificate, err := keyClient.SignVerbatim(ctx, csr, &SignVerbatimOptions{
			TTL: "1h",
		})
		if err != nil {
			t.Fatalf("KeyClient.SignVerbatim failed: %v", err)
		}

		if certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if certificate.Certificate.Subject.CommonName != "keyclient-verbatim.example.com" {
			t.Errorf("Expected CN 'keyclient-verbatim.example.com', got '%s'", certificate.Certificate.Subject.CommonName)
		}
	})
}

// setupRootCAAndRoleForKeyTests sets up a root CA and test role for key integration tests
func setupRootCAAndRoleForKeyTests(t *testing.T, ctx context.Context, client *Client) {
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
