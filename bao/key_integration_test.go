//go:build integration

package bao

import (
	"context"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair/algo"
)

func TestIntegration_KeyManagement(t *testing.T) {
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

	t.Run("Generate RSA key", func(t *testing.T) {
		keyInfo, err := client.GenerateKey(ctx, &GenerateKeyOptions{
			KeyName: "test-rsa-key",
			KeyType: "rsa",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if keyInfo.KeyID == "" {
			t.Error("Expected key ID, got empty string")
		}
		if keyInfo.KeyName != "test-rsa-key" {
			t.Errorf("Expected key name 'test-rsa-key', got '%s'", keyInfo.KeyName)
		}
		if keyInfo.KeyType != "rsa" {
			t.Errorf("Expected key type 'rsa', got '%s'", keyInfo.KeyType)
		}
		// Note: OpenBao API doesn't return key_bits in response
	})

	t.Run("Generate ECDSA key", func(t *testing.T) {
		keyInfo, err := client.GenerateKey(ctx, &GenerateKeyOptions{
			KeyName: "test-ec-key",
			KeyType: "ec",
			KeyBits: 256,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if keyInfo.KeyType != "ec" {
			t.Errorf("Expected key type 'ec', got '%s'", keyInfo.KeyType)
		}
		// Note: OpenBao API doesn't return key_bits in response
	})

	t.Run("Generate Ed25519 key", func(t *testing.T) {
		keyInfo, err := client.GenerateKey(ctx, &GenerateKeyOptions{
			KeyName: "test-ed25519-key",
			KeyType: "ed25519",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if keyInfo.KeyType != "ed25519" {
			t.Errorf("Expected key type 'ed25519', got '%s'", keyInfo.KeyType)
		}
	})

	t.Run("List keys", func(t *testing.T) {
		keys, err := client.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		if len(keys) < 3 {
			t.Errorf("Expected at least 3 keys, got %d", len(keys))
		}

		// Check that our keys are in the list
		foundRSA := false
		foundEC := false
		foundEd25519 := false
		for _, keyID := range keys {
			info, err := client.GetKey(ctx, keyID)
			if err != nil {
				continue
			}
			if info.KeyName == "test-rsa-key" {
				foundRSA = true
			}
			if info.KeyName == "test-ec-key" {
				foundEC = true
			}
			if info.KeyName == "test-ed25519-key" {
				foundEd25519 = true
			}
		}

		if !foundRSA {
			t.Error("test-rsa-key not found in list")
		}
		if !foundEC {
			t.Error("test-ec-key not found in list")
		}
		if !foundEd25519 {
			t.Error("test-ed25519-key not found in list")
		}
	})

	t.Run("Get key", func(t *testing.T) {
		// First generate a key
		keyInfo, err := client.GenerateKey(ctx, &GenerateKeyOptions{
			KeyName: "get-test-key",
			KeyType: "rsa",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Get key by ID
		retrievedKey, err := client.GetKey(ctx, keyInfo.KeyID)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		if retrievedKey.KeyID != keyInfo.KeyID {
			t.Errorf("Expected key ID %s, got %s", keyInfo.KeyID, retrievedKey.KeyID)
		}
		if retrievedKey.KeyName != "get-test-key" {
			t.Errorf("Expected key name 'get-test-key', got '%s'", retrievedKey.KeyName)
		}
	})

	t.Run("Update key name", func(t *testing.T) {
		// Generate a key
		keyInfo, err := client.GenerateKey(ctx, &GenerateKeyOptions{
			KeyName: "old-name",
			KeyType: "rsa",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Update name
		err = client.UpdateKeyName(ctx, keyInfo.KeyID, "new-name")
		if err != nil {
			t.Fatalf("UpdateKeyName failed: %v", err)
		}

		// Verify update
		updatedKey, err := client.GetKey(ctx, keyInfo.KeyID)
		if err != nil {
			t.Fatalf("GetKey after update failed: %v", err)
		}

		if updatedKey.KeyName != "new-name" {
			t.Errorf("Expected key name 'new-name', got '%s'", updatedKey.KeyName)
		}
	})

	t.Run("Delete key", func(t *testing.T) {
		// Generate a key
		keyInfo, err := client.GenerateKey(ctx, &GenerateKeyOptions{
			KeyName: "delete-test-key",
			KeyType: "rsa",
			KeyBits: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Delete key
		err = client.DeleteKey(ctx, keyInfo.KeyID)
		if err != nil {
			t.Fatalf("DeleteKey failed: %v", err)
		}

		// Verify deletion
		_, err = client.GetKey(ctx, keyInfo.KeyID)
		if err == nil {
			t.Error("Expected error when getting deleted key, got nil")
		}
	})
}

func TestIntegration_KeyImport(t *testing.T) {
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

	t.Run("Import RSA key", func(t *testing.T) {
		// Generate RSA key pair locally
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair failed: %v", err)
		}

		// Import key
		keyInfo, err := client.ImportKey(ctx, keyPair, &ImportKeyOptions{
			KeyName: "imported-rsa-key",
		})
		if err != nil {
			t.Fatalf("ImportKey failed: %v", err)
		}

		if keyInfo.KeyID == "" {
			t.Error("Expected key ID, got empty string")
		}
		if keyInfo.KeyName != "imported-rsa-key" {
			t.Errorf("Expected key name 'imported-rsa-key', got '%s'", keyInfo.KeyName)
		}
		if keyInfo.KeyType != "rsa" {
			t.Errorf("Expected key type 'rsa', got '%s'", keyInfo.KeyType)
		}
		if keyInfo.KeyBits != 2048 {
			t.Errorf("Expected key bits 2048, got %d", keyInfo.KeyBits)
		}
	})

	t.Run("Import ECDSA key", func(t *testing.T) {
		// Generate ECDSA key pair locally
		keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("GenerateECDSAKeyPair failed: %v", err)
		}

		// Import key
		keyInfo, err := client.ImportKey(ctx, keyPair, &ImportKeyOptions{
			KeyName: "imported-ec-key",
		})
		if err != nil {
			t.Fatalf("ImportKey failed: %v", err)
		}

		if keyInfo.KeyType != "ec" {
			t.Errorf("Expected key type 'ec', got '%s'", keyInfo.KeyType)
		}
		if keyInfo.KeyBits != 256 {
			t.Errorf("Expected key bits 256, got %d", keyInfo.KeyBits)
		}
	})

	t.Run("Import Ed25519 key", func(t *testing.T) {
		// Generate Ed25519 key pair locally
		keyPair, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
		}

		// Import key
		keyInfo, err := client.ImportKey(ctx, keyPair, &ImportKeyOptions{
			KeyName: "imported-ed25519-key",
		})
		if err != nil {
			t.Fatalf("ImportKey failed: %v", err)
		}

		if keyInfo.KeyType != "ed25519" {
			t.Errorf("Expected key type 'ed25519', got '%s'", keyInfo.KeyType)
		}
	})
}

func TestIntegration_KeyExport(t *testing.T) {
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

t.Run("Export RSA key", func(t *testing.T) {
// Generate and import RSA key locally so we can export it
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
if err != nil {
t.Fatalf("GenerateRSAKeyPair failed: %v", err)
}

// Import key
keyInfo, err := client.ImportKey(ctx, keyPair, &ImportKeyOptions{
KeyName: "exportable-rsa-key",
})
if err != nil {
t.Fatalf("ImportKey failed: %v", err)
}

// Export key
exportedKey, err := client.ExportRSAKey(ctx, keyInfo.KeyID)
if err != nil {
t.Fatalf("ExportRSAKey failed: %v", err)
}

// Validate exported key
if exportedKey == nil {
t.Fatal("Expected exported key, got nil")
}
if exportedKey.PrivateKey == nil {
t.Error("Expected non-nil private key")
}
if exportedKey.PublicKey == nil {
t.Error("Expected non-nil public key")
}

// Verify key size
if exportedKey.PrivateKey.N.BitLen() != 2048 {
t.Errorf("Expected 2048-bit key, got %d bits", exportedKey.PrivateKey.N.BitLen())
}
})

t.Run("Export ECDSA key", func(t *testing.T) {
// Generate and import ECDSA key locally
keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
if err != nil {
t.Fatalf("GenerateECDSAKeyPair failed: %v", err)
}

// Import key
keyInfo, err := client.ImportKey(ctx, keyPair, &ImportKeyOptions{
KeyName: "exportable-ec-key",
})
if err != nil {
t.Fatalf("ImportKey failed: %v", err)
}

// Export key
exportedKey, err := client.ExportECDSAKey(ctx, keyInfo.KeyID)
if err != nil {
t.Fatalf("ExportECDSAKey failed: %v", err)
}

// Validate exported key
if exportedKey == nil {
t.Fatal("Expected exported key, got nil")
}
if exportedKey.PrivateKey == nil {
t.Error("Expected non-nil private key")
}
if exportedKey.PublicKey == nil {
t.Error("Expected non-nil public key")
}

// Verify curve
if exportedKey.PrivateKey.Curve.Params().BitSize != 256 {
t.Errorf("Expected P-256 curve, got %d-bit curve", exportedKey.PrivateKey.Curve.Params().BitSize)
}
})

t.Run("Export Ed25519 key", func(t *testing.T) {
// Generate and import Ed25519 key locally
keyPair, err := algo.GenerateEd25519KeyPair()
if err != nil {
t.Fatalf("GenerateEd25519KeyPair failed: %v", err)
}

// Import key
keyInfo, err := client.ImportKey(ctx, keyPair, &ImportKeyOptions{
KeyName: "exportable-ed25519-key",
})
if err != nil {
t.Fatalf("ImportKey failed: %v", err)
}

// Export key
exportedKey, err := client.ExportEd25519Key(ctx, keyInfo.KeyID)
if err != nil {
t.Fatalf("ExportEd25519Key failed: %v", err)
}

// Validate exported key
if exportedKey == nil {
t.Fatal("Expected exported key, got nil")
}
if len(exportedKey.PrivateKey) == 0 {
t.Error("Expected non-empty private key")
}
if len(exportedKey.PublicKey) == 0 {
t.Error("Expected non-empty public key")
}

// Verify key size (Ed25519 is always 256 bits / 32 bytes for public key)
if len(exportedKey.PublicKey) != 32 {
t.Errorf("Expected 32-byte public key, got %d bytes", len(exportedKey.PublicKey))
}
})
}
