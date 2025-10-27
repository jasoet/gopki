//go:build integration

package vault

import (
	"context"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
)

func TestIntegration_KeyManagement(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)
	vaultContainer.WaitForVaultReady(ctx, t, client)
	vaultContainer.EnablePKI(ctx, t, client)

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

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)
	vaultContainer.WaitForVaultReady(ctx, t, client)
	vaultContainer.EnablePKI(ctx, t, client)

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
