//go:build integration

package transit_test

import (
	"context"
	"testing"

	"github.com/jasoet/gopki/bao/transit"
)

// TestIntegration_KeyLifecycle tests complete key lifecycle operations.
func TestIntegration_KeyLifecycle(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "integration-test-key"

	// 1. Create AES256 key
	keyClient, err := client.CreateAES256Key(ctx, keyName, &transit.CreateKeyOptions{
		Derived:    false,
		Exportable: true, // Make exportable for later tests
	})
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Verify key name
	if keyClient.Name() != keyName {
		t.Errorf("KeyClient.Name() = %v, want %v", keyClient.Name(), keyName)
	}

	// 2. Get key info
	keyInfo, err := keyClient.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo() error = %v", err)
	}

	if keyInfo.Name != keyName {
		t.Errorf("KeyInfo.Name = %v, want %v", keyInfo.Name, keyName)
	}

	if keyInfo.Type != transit.KeyTypeAES256GCM96 {
		t.Errorf("KeyInfo.Type = %v, want %v", keyInfo.Type, transit.KeyTypeAES256GCM96)
	}

	if keyInfo.LatestVersion != 1 {
		t.Errorf("KeyInfo.LatestVersion = %v, want 1", keyInfo.LatestVersion)
	}

	if !keyInfo.Exportable {
		t.Error("KeyInfo.Exportable should be true")
	}

	// 3. Update key configuration
	minEncVer := 1
	err = keyClient.Update(ctx, &transit.UpdateKeyOptions{
		MinEncryptionVersion: &minEncVer,
		DeletionAllowed:      boolPtr(true),
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	keyInfo, err = keyClient.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo() after update error = %v", err)
	}

	if keyInfo.MinEncryptionVersion != 1 {
		t.Errorf("KeyInfo.MinEncryptionVersion = %v, want 1", keyInfo.MinEncryptionVersion)
	}

	if !keyInfo.DeletionAllowed {
		t.Error("KeyInfo.DeletionAllowed should be true after update")
	}

	// 4. Rotate key
	err = keyClient.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// Verify rotation
	keyInfo, err = keyClient.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo() after rotation error = %v", err)
	}

	if keyInfo.LatestVersion != 2 {
		t.Errorf("KeyInfo.LatestVersion after rotation = %v, want 2", keyInfo.LatestVersion)
	}

	// 5. Rotate again
	err = keyClient.Rotate(ctx)
	if err != nil {
		t.Fatalf("Second Rotate() error = %v", err)
	}

	keyInfo, err = keyClient.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo() after second rotation error = %v", err)
	}

	if keyInfo.LatestVersion != 3 {
		t.Errorf("KeyInfo.LatestVersion after second rotation = %v, want 3", keyInfo.LatestVersion)
	}

	// 6. Update MinEncryptionVersion and MinDecryptionVersion before trimming
	minVer2 := 2
	err = keyClient.Update(ctx, &transit.UpdateKeyOptions{
		MinEncryptionVersion: &minVer2,
		MinDecryptionVersion: &minVer2,
	})
	if err != nil {
		t.Fatalf("Update() before trim error = %v", err)
	}

	// 7. Trim old versions
	err = keyClient.TrimVersions(ctx, 2)
	if err != nil {
		t.Fatalf("TrimVersions() error = %v", err)
	}

	// Verify trim by checking MinDecryptionVersion
	keyInfo, err = keyClient.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo() after trim error = %v", err)
	}

	// After trimming, MinDecryptionVersion should be 2
	if keyInfo.MinDecryptionVersion != 2 {
		t.Errorf("MinDecryptionVersion after trim = %v, want 2", keyInfo.MinDecryptionVersion)
	}

	// LatestVersion should still be 3
	if keyInfo.LatestVersion != 3 {
		t.Errorf("LatestVersion after trim = %v, want 3", keyInfo.LatestVersion)
	}

	// 8. List keys
	keys, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	found := false
	for _, k := range keys {
		if k == keyName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListKeys() does not contain %v", keyName)
	}

	// 9. Delete key
	err = keyClient.Delete(ctx)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	_, err = client.GetKey(ctx, keyName)
	if err == nil {
		t.Error("GetKey() after deletion should return error")
	}
}

// TestIntegration_MultipleKeyTypes tests creating different key types.
func TestIntegration_MultipleKeyTypes(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	tests := []struct {
		name       string
		createFunc func() error
		keyType    string
	}{
		{
			name: "AES128",
			createFunc: func() error {
				_, err := client.CreateAES128Key(ctx, "test-aes128", nil)
				return err
			},
			keyType: transit.KeyTypeAES128GCM96,
		},
		{
			name: "AES256",
			createFunc: func() error {
				_, err := client.CreateAES256Key(ctx, "test-aes256", nil)
				return err
			},
			keyType: transit.KeyTypeAES256GCM96,
		},
		{
			name: "ChaCha20",
			createFunc: func() error {
				_, err := client.CreateChaCha20Key(ctx, "test-chacha20", nil)
				return err
			},
			keyType: transit.KeyTypeChaCha20Poly1305,
		},
		{
			name: "RSA2048",
			createFunc: func() error {
				_, err := client.CreateRSA2048Key(ctx, "test-rsa2048", nil)
				return err
			},
			keyType: transit.KeyTypeRSA2048,
		},
		{
			name: "ECDSA P256",
			createFunc: func() error {
				_, err := client.CreateECDSAP256Key(ctx, "test-ecdsa-p256", nil)
				return err
			},
			keyType: transit.KeyTypeECDSAP256,
		},
		{
			name: "Ed25519",
			createFunc: func() error {
				_, err := client.CreateEd25519Key(ctx, "test-ed25519", nil)
				return err
			},
			keyType: transit.KeyTypeEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.createFunc()
			if err != nil {
				t.Errorf("Create %s key error = %v", tt.name, err)
			}
		})
	}
}

// TestIntegration_TypeSafeGetters tests type-safe key retrieval.
func TestIntegration_TypeSafeGetters(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "type-safe-key"

	// Create AES256 key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Get with type-safe getter
	keyClient, err := client.GetAES256Key(ctx, keyName)
	if err != nil {
		t.Fatalf("GetAES256Key() error = %v", err)
	}

	if keyClient.Name() != keyName {
		t.Errorf("KeyClient.Name() = %v, want %v", keyClient.Name(), keyName)
	}

	// Verify type
	keyType := keyClient.Type()
	if keyType.KeyTypeName() != transit.KeyTypeAES256GCM96 {
		t.Errorf("KeyClient.Type().KeyTypeName() = %v, want %v",
			keyType.KeyTypeName(), transit.KeyTypeAES256GCM96)
	}
}
