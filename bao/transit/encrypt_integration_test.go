//go:build integration

package transit_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jasoet/gopki/bao/transit"
)

// TestIntegration_EncryptDecrypt tests basic encryption and decryption.
func TestIntegration_EncryptDecrypt(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-encrypt-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Encrypt data
	plaintext := base64.StdEncoding.EncodeToString([]byte("hello world"))
	encResult, err := client.Encrypt(ctx, keyName, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if encResult.Ciphertext == "" {
		t.Error("Encrypt() returned empty ciphertext")
	}

	// Verify ciphertext format (should start with "vault:v")
	if !strings.HasPrefix(encResult.Ciphertext, "vault:v") {
		t.Errorf("Ciphertext format invalid: %s", encResult.Ciphertext)
	}

	// Decrypt data
	decResult, err := client.Decrypt(ctx, keyName, encResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Errorf("Decrypted plaintext = %v, want %v", decResult.Plaintext, plaintext)
	}

	// Verify the decrypted data matches original
	decryptedBytes, _ := base64.StdEncoding.DecodeString(decResult.Plaintext)
	if string(decryptedBytes) != "hello world" {
		t.Errorf("Decrypted data = %v, want 'hello world'", string(decryptedBytes))
	}
}

// TestIntegration_EncryptWithOptions tests encryption with various options.
func TestIntegration_EncryptWithOptions(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-encrypt-opts-key"

	// Create key with derived=true for context-based encryption
	_, err := client.CreateAES256Key(ctx, keyName, &transit.CreateKeyOptions{
		Derived: true,
	})
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("sensitive data"))
	context := base64.StdEncoding.EncodeToString([]byte("user-123"))

	// Encrypt with context
	encResult, err := client.Encrypt(ctx, keyName, plaintext, &transit.EncryptOptions{
		Context: context,
	})
	if err != nil {
		t.Fatalf("Encrypt() with context error = %v", err)
	}

	// Decrypt with same context
	decResult, err := client.Decrypt(ctx, keyName, encResult.Ciphertext, &transit.DecryptOptions{
		Context: context,
	})
	if err != nil {
		t.Fatalf("Decrypt() with context error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Errorf("Decrypted plaintext = %v, want %v", decResult.Plaintext, plaintext)
	}

	// Try to decrypt with wrong context (should fail)
	wrongContext := base64.StdEncoding.EncodeToString([]byte("user-456"))
	_, err = client.Decrypt(ctx, keyName, encResult.Ciphertext, &transit.DecryptOptions{
		Context: wrongContext,
	})
	if err == nil {
		t.Error("Decrypt() with wrong context should fail")
	}
}

// TestIntegration_BatchEncryptDecrypt tests batch operations.
func TestIntegration_BatchEncryptDecrypt(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-batch-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Prepare batch data
	items := []transit.BatchEncryptItem{
		{Plaintext: base64.StdEncoding.EncodeToString([]byte("data1"))},
		{Plaintext: base64.StdEncoding.EncodeToString([]byte("data2"))},
		{Plaintext: base64.StdEncoding.EncodeToString([]byte("data3"))},
	}

	// Batch encrypt
	encResult, err := client.EncryptBatch(ctx, keyName, items)
	if err != nil {
		t.Fatalf("EncryptBatch() error = %v", err)
	}

	if len(encResult.Results) != 3 {
		t.Errorf("EncryptBatch() returned %d results, want 3", len(encResult.Results))
	}

	// Check for errors
	for i, err := range encResult.Errors {
		if err != nil {
			t.Errorf("EncryptBatch() item %d error: %v", i, err)
		}
	}

	// Prepare batch decrypt
	decItems := make([]transit.BatchDecryptItem, len(encResult.Results))
	for i, result := range encResult.Results {
		decItems[i] = transit.BatchDecryptItem{
			Ciphertext: result.Ciphertext,
		}
	}

	// Batch decrypt
	decResult, err := client.DecryptBatch(ctx, keyName, decItems)
	if err != nil {
		t.Fatalf("DecryptBatch() error = %v", err)
	}

	if len(decResult.Results) != 3 {
		t.Errorf("DecryptBatch() returned %d results, want 3", len(decResult.Results))
	}

	// Verify decrypted data
	expected := []string{"data1", "data2", "data3"}
	for i, result := range decResult.Results {
		if decResult.Errors[i] != nil {
			t.Errorf("DecryptBatch() item %d error: %v", i, decResult.Errors[i])
			continue
		}

		decrypted, _ := base64.StdEncoding.DecodeString(result.Plaintext)
		if string(decrypted) != expected[i] {
			t.Errorf("DecryptBatch() item %d = %s, want %s", i, string(decrypted), expected[i])
		}
	}
}

// TestIntegration_LargeBatchAutoChunking tests automatic chunking for large batches.
func TestIntegration_LargeBatchAutoChunking(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-large-batch-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Create a large batch (300 items, exceeds default 250 chunk size)
	items := make([]transit.BatchEncryptItem, 300)
	for i := range items {
		data := []byte(base64.StdEncoding.EncodeToString([]byte("test")))
		items[i] = transit.BatchEncryptItem{
			Plaintext: string(data),
		}
	}

	// Should automatically chunk
	result, err := client.EncryptBatch(ctx, keyName, items)
	if err != nil {
		t.Fatalf("EncryptBatch() with 300 items error = %v", err)
	}

	if len(result.Results) != 300 {
		t.Errorf("EncryptBatch() returned %d results, want 300", len(result.Results))
	}

	// Check all succeeded
	errorCount := 0
	for _, err := range result.Errors {
		if err != nil {
			errorCount++
		}
	}

	if errorCount > 0 {
		t.Errorf("EncryptBatch() had %d errors out of 300", errorCount)
	}
}

// TestIntegration_ReEncrypt tests re-encryption for key rotation.
func TestIntegration_ReEncrypt(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-reencrypt-key"

	// Create key
	keyClient, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Encrypt with version 1
	plaintext := base64.StdEncoding.EncodeToString([]byte("secret"))
	encResult, err := client.Encrypt(ctx, keyName, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Verify it's version 1
	if !strings.Contains(encResult.Ciphertext, ":v1:") {
		t.Errorf("Ciphertext should be v1, got: %s", encResult.Ciphertext)
	}

	// Rotate key to version 2
	err = keyClient.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// Re-encrypt to version 2
	reencResult, err := client.ReEncrypt(ctx, keyName, encResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("ReEncrypt() error = %v", err)
	}

	// Verify it's now version 2
	if !strings.Contains(reencResult.Ciphertext, ":v2:") {
		t.Errorf("Re-encrypted ciphertext should be v2, got: %s", reencResult.Ciphertext)
	}

	// Decrypt and verify data unchanged
	decResult, err := client.Decrypt(ctx, keyName, reencResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() after reencrypt error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Errorf("Decrypted plaintext = %v, want %v", decResult.Plaintext, plaintext)
	}
}

// TestIntegration_GenerateDataKey tests data key generation for envelope encryption.
func TestIntegration_GenerateDataKey(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-datakey-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Generate data key with plaintext
	dataKey, err := client.GenerateDataKey(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("GenerateDataKey() error = %v", err)
	}

	if dataKey.Plaintext == "" {
		t.Error("GenerateDataKey() returned empty plaintext")
	}

	if dataKey.Ciphertext == "" {
		t.Error("GenerateDataKey() returned empty ciphertext")
	}

	// Verify ciphertext format
	if !strings.HasPrefix(dataKey.Ciphertext, "vault:v") {
		t.Errorf("Data key ciphertext format invalid: %s", dataKey.Ciphertext)
	}

	// Decrypt the wrapped data key
	decResult, err := client.Decrypt(ctx, keyName, dataKey.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() data key error = %v", err)
	}

	// Verify decrypted key matches plaintext
	if decResult.Plaintext != dataKey.Plaintext {
		t.Error("Decrypted data key doesn't match plaintext data key")
	}

	// Verify key length (should be 256 bits / 32 bytes = 44 base64 chars with padding)
	keyBytes, _ := base64.StdEncoding.DecodeString(dataKey.Plaintext)
	if len(keyBytes) != 32 {
		t.Errorf("Data key length = %d bytes, want 32", len(keyBytes))
	}
}

// TestIntegration_GenerateDataKeyWithOptions tests data key generation with options.
func TestIntegration_GenerateDataKeyWithOptions(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-datakey-opts-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Generate 128-bit data key
	dataKey, err := client.GenerateDataKey(ctx, keyName, &transit.DataKeyOptions{
		Bits: 128,
	})
	if err != nil {
		t.Fatalf("GenerateDataKey() error = %v", err)
	}

	// Verify key length (should be 128 bits / 16 bytes)
	keyBytes, _ := base64.StdEncoding.DecodeString(dataKey.Plaintext)
	if len(keyBytes) != 16 {
		t.Errorf("Data key length = %d bytes, want 16", len(keyBytes))
	}
}

// TestIntegration_GenerateWrappedDataKey tests wrapped-only data key generation.
func TestIntegration_GenerateWrappedDataKey(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-wrapped-datakey-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Generate wrapped data key (no plaintext)
	dataKey, err := client.GenerateWrappedDataKey(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("GenerateWrappedDataKey() error = %v", err)
	}

	if dataKey.Plaintext != "" {
		t.Error("GenerateWrappedDataKey() should not return plaintext")
	}

	if dataKey.Ciphertext == "" {
		t.Error("GenerateWrappedDataKey() returned empty ciphertext")
	}

	// Verify we can decrypt it
	decResult, err := client.Decrypt(ctx, keyName, dataKey.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() wrapped data key error = %v", err)
	}

	// Should have valid plaintext key
	keyBytes, _ := base64.StdEncoding.DecodeString(decResult.Plaintext)
	if len(keyBytes) != 32 {
		t.Errorf("Wrapped data key length = %d bytes, want 32", len(keyBytes))
	}
}

// TestIntegration_EncryptWithKeyVersion tests encryption with specific key version.
func TestIntegration_EncryptWithKeyVersion(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-version-key"

	// Create key and rotate twice
	keyClient, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	keyClient.Rotate(ctx) // v2
	keyClient.Rotate(ctx) // v3

	plaintext := base64.StdEncoding.EncodeToString([]byte("version test"))

	// Encrypt with version 2
	encResult, err := client.Encrypt(ctx, keyName, plaintext, &transit.EncryptOptions{
		KeyVersion: 2,
	})
	if err != nil {
		t.Fatalf("Encrypt() with version 2 error = %v", err)
	}

	// Verify it's version 2
	if !strings.Contains(encResult.Ciphertext, ":v2:") {
		t.Errorf("Ciphertext should be v2, got: %s", encResult.Ciphertext)
	}

	// Encrypt with latest (v3)
	encResult3, err := client.Encrypt(ctx, keyName, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() with latest error = %v", err)
	}

	// Verify it's version 3
	if !strings.Contains(encResult3.Ciphertext, ":v3:") {
		t.Errorf("Ciphertext should be v3, got: %s", encResult3.Ciphertext)
	}

	// Both should decrypt to same plaintext
	dec2, _ := client.Decrypt(ctx, keyName, encResult.Ciphertext, nil)
	dec3, _ := client.Decrypt(ctx, keyName, encResult3.Ciphertext, nil)

	if dec2.Plaintext != plaintext || dec3.Plaintext != plaintext {
		t.Error("Decrypted data doesn't match original")
	}
}

// TestIntegration_ConvergentEncryption tests convergent encryption with nonce.
func TestIntegration_ConvergentEncryption(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-convergent-key"

	// Create key with convergent encryption
	_, err := client.CreateAES256Key(ctx, keyName, &transit.CreateKeyOptions{
		Derived:              true,
		ConvergentEncryption: true,
	})
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("convergent data"))
	context := base64.StdEncoding.EncodeToString([]byte("user-123"))
	nonce := base64.StdEncoding.EncodeToString([]byte("unique-nonce-123"))

	// Encrypt twice with same context and nonce
	result1, err := client.Encrypt(ctx, keyName, plaintext, &transit.EncryptOptions{
		Context: context,
		Nonce:   nonce,
	})
	if err != nil {
		t.Fatalf("First Encrypt() error = %v", err)
	}

	result2, err := client.Encrypt(ctx, keyName, plaintext, &transit.EncryptOptions{
		Context: context,
		Nonce:   nonce,
	})
	if err != nil {
		t.Fatalf("Second Encrypt() error = %v", err)
	}

	// With convergent encryption, same plaintext + context + nonce = same ciphertext
	if result1.Ciphertext != result2.Ciphertext {
		t.Error("Convergent encryption should produce same ciphertext for same inputs")
	}

	// Different plaintext should produce different ciphertext
	differentPlaintext := base64.StdEncoding.EncodeToString([]byte("different data"))
	result3, err := client.Encrypt(ctx, keyName, differentPlaintext, &transit.EncryptOptions{
		Context: context,
		Nonce:   nonce,
	})
	if err != nil {
		t.Fatalf("Encrypt() with different plaintext error = %v", err)
	}

	if result1.Ciphertext == result3.Ciphertext {
		t.Error("Different plaintext should produce different ciphertext")
	}
}

// TestIntegration_EncryptDecryptErrors tests error scenarios.
func TestIntegration_EncryptDecryptErrors(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-error-key"

	// Create derived key (requires context)
	_, err := client.CreateAES256Key(ctx, keyName, &transit.CreateKeyOptions{
		Derived: true,
	})
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("test"))
	context := base64.StdEncoding.EncodeToString([]byte("ctx"))

	// Encrypt WITH context
	result, err := client.Encrypt(ctx, keyName, plaintext, &transit.EncryptOptions{
		Context: context,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt WITHOUT context (should fail)
	_, err = client.Decrypt(ctx, keyName, result.Ciphertext, nil)
	if err == nil {
		t.Error("Decrypt() without context should fail for derived key")
	}

	// Try to decrypt with WRONG context (should fail)
	wrongContext := base64.StdEncoding.EncodeToString([]byte("wrong"))
	_, err = client.Decrypt(ctx, keyName, result.Ciphertext, &transit.DecryptOptions{
		Context: wrongContext,
	})
	if err == nil {
		t.Error("Decrypt() with wrong context should fail")
	}

	// Decrypt with correct context (should succeed)
	decResult, err := client.Decrypt(ctx, keyName, result.Ciphertext, &transit.DecryptOptions{
		Context: context,
	})
	if err != nil {
		t.Fatalf("Decrypt() with correct context error = %v", err)
	}
	if decResult.Plaintext != plaintext {
		t.Error("Decrypted plaintext doesn't match")
	}
}

// TestIntegration_BatchDecryptWithWrongKey tests that decrypting with wrong key fails.
func TestIntegration_BatchDecryptWithWrongKey(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName1 := "test-batch-wrongkey-1"
	keyName2 := "test-batch-wrongkey-2"

	// Create two different keys
	_, err := client.CreateAES256Key(ctx, keyName1, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key(key1) error = %v", err)
	}

	_, err = client.CreateAES256Key(ctx, keyName2, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key(key2) error = %v", err)
	}

	// Encrypt with key1
	plaintext := base64.StdEncoding.EncodeToString([]byte("secret data"))
	encResult, err := client.Encrypt(ctx, keyName1, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with key2 (wrong key) - should fail
	_, err = client.Decrypt(ctx, keyName2, encResult.Ciphertext, nil)
	if err == nil {
		t.Error("Decrypt() with wrong key should fail")
	}

	// Decrypt with correct key - should succeed
	decResult, err := client.Decrypt(ctx, keyName1, encResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() with correct key error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Errorf("Decrypted plaintext = %v, want %v", decResult.Plaintext, plaintext)
	}
}

// TestIntegration_ChaCha20Encryption tests encryption with ChaCha20-Poly1305.
func TestIntegration_ChaCha20Encryption(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-chacha20-key"

	// Create ChaCha20 key
	_, err := client.CreateChaCha20Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateChaCha20Key() error = %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("chacha20 data"))

	// Encrypt
	encResult, err := client.Encrypt(ctx, keyName, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decrypt
	decResult, err := client.Decrypt(ctx, keyName, encResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Error("Decrypted plaintext doesn't match")
	}
}

// TestIntegration_MultipleKeyRotationsReEncrypt tests multiple rotations and re-encryption.
func TestIntegration_MultipleKeyRotationsReEncrypt(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-multi-rotate-key"

	// Create key
	keyClient, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("multi-rotation test"))

	// Encrypt with v1
	encV1, err := client.Encrypt(ctx, keyName, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Rotate 5 times (v1 -> v6)
	for i := 0; i < 5; i++ {
		err = keyClient.Rotate(ctx)
		if err != nil {
			t.Fatalf("Rotate() iteration %d error = %v", i, err)
		}
	}

	// Re-encrypt to latest version (v6)
	reencResult, err := client.ReEncrypt(ctx, keyName, encV1.Ciphertext, nil)
	if err != nil {
		t.Fatalf("ReEncrypt() error = %v", err)
	}

	// Verify it's now v6
	if !strings.Contains(reencResult.Ciphertext, ":v6:") {
		t.Errorf("Re-encrypted should be v6, got: %s", reencResult.Ciphertext)
	}

	// Verify data integrity
	decResult, err := client.Decrypt(ctx, keyName, reencResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() after multiple rotations error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Error("Plaintext mismatch after multiple rotations")
	}
}

// TestIntegration_ImportKeyThenEncrypt tests importing a key and using it for encryption.
func TestIntegration_ImportKeyThenEncrypt(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-import-encrypt-key"

	// Generate AES-256 key
	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	if err != nil {
		t.Fatalf("Generate key: %v", err)
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

	// Use imported key for encryption
	plaintext := base64.StdEncoding.EncodeToString([]byte("imported key test"))
	encResult, err := client.Encrypt(ctx, keyName, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() with imported key error = %v", err)
	}

	// Decrypt
	decResult, err := client.Decrypt(ctx, keyName, encResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decResult.Plaintext != plaintext {
		t.Error("Decrypted plaintext doesn't match")
	}
}

// TestIntegration_EncryptEmptyData tests encryption of empty data.
func TestIntegration_EncryptEmptyData(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-empty-data-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Try to encrypt empty plaintext (should fail at validation)
	_, err = client.Encrypt(ctx, keyName, "", nil)
	if err == nil {
		t.Error("Encrypt() with empty plaintext should fail")
	}
}

// TestIntegration_DataKeyRotation tests data key generation after key rotation.
func TestIntegration_DataKeyRotation(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-datakey-rotation-key"

	// Create key
	keyClient, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Generate data key with v1
	dataKey1, err := client.GenerateDataKey(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("GenerateDataKey() v1 error = %v", err)
	}

	// Rotate key
	keyClient.Rotate(ctx)

	// Generate data key with v2
	dataKey2, err := client.GenerateDataKey(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("GenerateDataKey() v2 error = %v", err)
	}

	// Keys should be different
	if dataKey1.Plaintext == dataKey2.Plaintext {
		t.Error("Data keys should be different")
	}

	// Both wrapped keys should decrypt successfully
	dec1, err := client.Decrypt(ctx, keyName, dataKey1.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() data key v1 error = %v", err)
	}
	if dec1.Plaintext != dataKey1.Plaintext {
		t.Error("Data key v1 mismatch")
	}

	dec2, err := client.Decrypt(ctx, keyName, dataKey2.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() data key v2 error = %v", err)
	}
	if dec2.Plaintext != dataKey2.Plaintext {
		t.Error("Data key v2 mismatch")
	}
}

// TestIntegration_BatchAutoChunkingVerification tests chunking with exact boundaries.
func TestIntegration_BatchAutoChunkingVerification(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-chunk-boundary-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Test exact chunk boundary (250)
	items250 := make([]transit.BatchEncryptItem, 250)
	for i := range items250 {
		items250[i] = transit.BatchEncryptItem{
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
	}

	result250, err := client.EncryptBatch(ctx, keyName, items250)
	if err != nil {
		t.Fatalf("EncryptBatch() 250 items error = %v", err)
	}
	if len(result250.Results) != 250 {
		t.Errorf("Expected 250 results, got %d", len(result250.Results))
	}

	// Test one over boundary (251 - should create 2 chunks)
	items251 := make([]transit.BatchEncryptItem, 251)
	for i := range items251 {
		items251[i] = transit.BatchEncryptItem{
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
	}

	result251, err := client.EncryptBatch(ctx, keyName, items251)
	if err != nil {
		t.Fatalf("EncryptBatch() 251 items error = %v", err)
	}
	if len(result251.Results) != 251 {
		t.Errorf("Expected 251 results, got %d", len(result251.Results))
	}

	// Verify all succeeded
	for i, err := range result251.Errors {
		if err != nil {
			t.Errorf("Item %d failed: %v", i, err)
		}
	}
}
