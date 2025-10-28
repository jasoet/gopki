// +build integration

package transit_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/jasoet/gopki/bao/transit"
)

// TestIntegration_KeyExport tests key export functionality.
func TestIntegration_KeyExport(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "exportable-key"

	// Create exportable key
	_, err := client.CreateAES256Key(ctx, keyName, &transit.CreateKeyOptions{
		Exportable: true,
	})
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Export key
	exported, err := client.ExportKey(ctx, keyName, transit.ExportEncryptionKey, 0)
	if err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}

	if len(exported) == 0 {
		t.Error("ExportKey() returned empty map")
	}

	// Should have version 1
	if _, exists := exported[1]; !exists {
		t.Error("Exported keys should contain version 1")
	}

	// Rotate and export all versions
	client.RotateKey(ctx, keyName)
	client.RotateKey(ctx, keyName)

	exported, err = client.ExportKey(ctx, keyName, transit.ExportEncryptionKey, 0)
	if err != nil {
		t.Fatalf("ExportKey() all versions error = %v", err)
	}

	if len(exported) != 3 {
		t.Errorf("Exported keys count = %v, want 3", len(exported))
	}

	// Export specific version
	exported, err = client.ExportKey(ctx, keyName, transit.ExportEncryptionKey, 2)
	if err != nil {
		t.Fatalf("ExportKey() version 2 error = %v", err)
	}

	if len(exported) != 1 {
		t.Errorf("Exported specific version count = %v, want 1", len(exported))
	}

	if _, exists := exported[2]; !exists {
		t.Error("Exported keys should contain version 2")
	}
}

// TestIntegration_KeyBackupRestore tests key backup and restore.
func TestIntegration_KeyBackupRestore(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "backup-key"
	restoredName := "restored-key"

	// Create key with plaintext backup allowed
	_, err := client.CreateAES256Key(ctx, keyName, &transit.CreateKeyOptions{
		Exportable:           true,
		AllowPlaintextBackup: true, // Required for backup
	})
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Backup key
	backup, err := client.BackupKey(ctx, keyName)
	if err != nil {
		t.Fatalf("BackupKey() error = %v", err)
	}

	if backup == "" {
		t.Error("BackupKey() returned empty string")
	}

	// Restore key with different name
	err = client.RestoreBackup(ctx, restoredName, backup)
	if err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}

	// Verify restored key
	restoredInfo, err := client.GetKey(ctx, restoredName)
	if err != nil {
		t.Fatalf("GetKey() restored key error = %v", err)
	}

	if restoredInfo.Type != transit.KeyTypeAES256GCM96 {
		t.Errorf("Restored key type = %v, want %v", restoredInfo.Type, transit.KeyTypeAES256GCM96)
	}
}

// TestIntegration_KeyImport tests key import functionality (BYOK).
func TestIntegration_KeyImport(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "imported-key"

	// Generate AES-256 key
	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	if err != nil {
		t.Fatalf("Generate random key: %v", err)
	}

	// Import key
	err = client.ImportKey(ctx, keyName, keyMaterial, &transit.ImportKeyOptions{
		Type:         transit.KeyTypeAES256GCM96,
		HashFunction: "SHA256",
		Exportable:   true,
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	// Verify imported key
	keyInfo, err := client.GetKey(ctx, keyName)
	if err != nil {
		t.Fatalf("GetKey() imported key error = %v", err)
	}

	if keyInfo.Type != transit.KeyTypeAES256GCM96 {
		t.Errorf("Imported key type = %v, want %v", keyInfo.Type, transit.KeyTypeAES256GCM96)
	}

	if !keyInfo.Exportable {
		t.Error("Imported key should be exportable")
	}

	// Export and verify it's the same key
	exported, err := client.ExportKey(ctx, keyName, transit.ExportEncryptionKey, 1)
	if err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}

	if len(exported) != 1 {
		t.Errorf("Exported key count = %v, want 1", len(exported))
	}
}

// TestIntegration_GetWrappingKey tests retrieving the wrapping key.
func TestIntegration_GetWrappingKey(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	wrappingKey, err := client.GetWrappingKey(ctx)
	if err != nil {
		t.Fatalf("GetWrappingKey() error = %v", err)
	}

	if wrappingKey == nil {
		t.Fatal("GetWrappingKey() returned nil")
	}

	if wrappingKey.PublicKey == nil {
		t.Error("WrappingKey.PublicKey is nil")
	}

	if wrappingKey.PEM == "" {
		t.Error("WrappingKey.PEM is empty")
	}

	// Verify RSA key size
	keyBits := wrappingKey.PublicKey.N.BitLen()
	if keyBits < 2048 {
		t.Errorf("Wrapping key size = %d bits, want >= 2048", keyBits)
	}
}
