package asymmetric

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEncryptWithEd25519(t *testing.T) {
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	opts := encryption.DefaultEncryptOptions()

	t.Run("ValidData", func(t *testing.T) {
		data := []byte("test data for Ed25519 encryption")

		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with Ed25519: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
		if encrypted.Algorithm != encryption.AlgorithmX25519 {
			t.Errorf("Expected algorithm %s, got %s", encryption.AlgorithmX25519, encrypted.Algorithm)
		}
		if len(encrypted.Data) == 0 {
			t.Error("Encrypted data is empty")
		}
		if len(encrypted.EncryptedKey) == 0 {
			t.Error("Ephemeral public key should be stored in EncryptedKey")
		}
		if len(encrypted.IV) == 0 {
			t.Error("IV should be present")
		}
		if len(encrypted.Tag) == 0 {
			t.Error("Authentication tag should be present")
		}
		if encrypted.Timestamp.IsZero() {
			t.Error("Timestamp should be set")
		}
		if encrypted.Format != opts.Format {
			t.Errorf("Expected format %s, got %s", opts.Format, encrypted.Format)
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		data := []byte("")

		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt empty data: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
	})

	t.Run("LargeData", func(t *testing.T) {
		// Ed25519 with AES-GCM can handle large data
		largeData := make([]byte, 100000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		encrypted, err := EncryptWithEd25519(largeData, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt large data: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
		if len(encrypted.Data) == 0 {
			t.Error("Encrypted data should not be empty for large input")
		}
	})

	t.Run("InvalidOptions", func(t *testing.T) {
		data := []byte("test data")
		invalidOpts := encryption.EncryptOptions{
			Algorithm: "invalid",
			Format:    encryption.FormatCMS,
		}

		_, err := EncryptWithEd25519(data, ed25519Keys, invalidOpts)
		if err == nil {
			t.Error("Expected error for invalid options")
		}
	})
}

func TestDecryptWithEd25519(t *testing.T) {
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()
	data := []byte("test data for Ed25519 decryption")

	t.Run("ValidDecryption", func(t *testing.T) {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match. Expected: %s, Got: %s", string(data), string(decrypted))
		}
	})

	t.Run("WrongAlgorithm", func(t *testing.T) {
		encrypted := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmECDH, // Wrong algorithm
			Data:      []byte("encrypted"),
		}

		_, err := DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
		if err == nil {
			t.Error("Expected error for wrong algorithm")
		}
		if !strings.Contains(err.Error(), "expected X25519") {
			t.Errorf("Expected algorithm error, got: %v", err)
		}
	})

	t.Run("InvalidEphemeralKey", func(t *testing.T) {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the ephemeral key
		encrypted.EncryptedKey = []byte("invalid ephemeral key")

		_, err = DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
		if err == nil {
			t.Error("Expected error for invalid ephemeral key")
		}
	})

	t.Run("CorruptedData", func(t *testing.T) {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the encrypted data
		encrypted.Data[0] ^= 0xFF

		_, err = DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
		if err == nil {
			t.Error("Expected error for corrupted data")
		}
	})

	t.Run("CorruptedIV", func(t *testing.T) {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the IV
		encrypted.IV[0] ^= 0xFF

		_, err = DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
		if err == nil {
			t.Error("Expected error for corrupted IV")
		}
	})

	t.Run("CorruptedTag", func(t *testing.T) {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the authentication tag
		encrypted.Tag[0] ^= 0xFF

		_, err = DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
		if err == nil {
			t.Error("Expected error for corrupted authentication tag")
		}
	})

	t.Run("WrongKeyPair", func(t *testing.T) {
		// Generate different key pair
		wrongKeys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate wrong Ed25519 key pair: %v", err)
		}

		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		_, err = DecryptWithEd25519(encrypted, wrongKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for wrong key pair")
		}
	})

	t.Run("InvalidDecryptOptions", func(t *testing.T) {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		invalidDecryptOpts := encryption.DecryptOptions{
			MaxAge: -1, // Invalid negative max age
		}

		_, err = DecryptWithEd25519(encrypted, ed25519Keys, invalidDecryptOpts)
		if err == nil {
			t.Error("Expected error for invalid decrypt options")
		}
	})
}

func TestEd25519RoundTrip(t *testing.T) {
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	dataSizes := []int{0, 1, 16, 100, 1024, 10000, 100000}
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	for _, size := range dataSizes {
		t.Run(fmt.Sprintf("Size%d", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt %d bytes: %v", size, err)
			}

			decrypted, err := DecryptWithEd25519(encrypted, ed25519Keys, decryptOpts)
			if err != nil {
				t.Fatalf("Failed to decrypt %d bytes: %v", size, err)
			}

			if len(decrypted) != len(data) {
				t.Errorf("Length mismatch. Expected: %d, Got: %d", len(data), len(decrypted))
			}

			for i := range data {
				if decrypted[i] != data[i] {
					t.Errorf("Data mismatch at position %d. Expected: %d, Got: %d", i, data[i], decrypted[i])
					break
				}
			}
		})
	}
}

func TestEd25519WithMetadata(t *testing.T) {
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	data := []byte("test data with metadata")
	opts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmX25519,
		Format:    encryption.FormatCMS,
		Metadata: map[string]interface{}{
			"algorithm": "Ed25519",
			"version":   1,
			"test_data": map[string]interface{}{
				"size": len(data),
				"type": "string",
			},
		},
	}

	encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if encrypted.Metadata == nil {
		t.Error("Metadata should be preserved")
	}

	if val, ok := encrypted.Metadata["algorithm"]; !ok || val != "Ed25519" {
		t.Error("String metadata not preserved correctly")
	}

	if val, ok := encrypted.Metadata["version"]; !ok || val != 1 {
		t.Error("Numeric metadata not preserved correctly")
	}

	if testData, ok := encrypted.Metadata["test_data"].(map[string]interface{}); !ok {
		t.Error("Nested metadata not preserved correctly")
	} else {
		if size, ok := testData["size"]; !ok || size != len(data) {
			t.Error("Nested size metadata not preserved correctly")
		}
		if typ, ok := testData["type"]; !ok || typ != "string" {
			t.Error("Nested type metadata not preserved correctly")
		}
	}
}

func TestEd25519KeyDerivation(t *testing.T) {
	// Test that Ed25519 to X25519 key derivation is consistent
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	data := []byte("test key derivation consistency")
	opts := encryption.DefaultEncryptOptions()

	// Encrypt multiple times with the same key pair
	encrypted1, err := EncryptWithEd25519(data, ed25519Keys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt first time: %v", err)
	}

	encrypted2, err := EncryptWithEd25519(data, ed25519Keys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt second time: %v", err)
	}

	// The ephemeral keys should be different (for forward secrecy)
	if string(encrypted1.EncryptedKey) == string(encrypted2.EncryptedKey) {
		t.Error("Ephemeral keys should be different for forward secrecy")
	}

	// But both should decrypt correctly with the same private key
	decrypted1, err := DecryptWithEd25519(encrypted1, ed25519Keys, encryption.DefaultDecryptOptions())
	if err != nil {
		t.Fatalf("Failed to decrypt first encryption: %v", err)
	}

	decrypted2, err := DecryptWithEd25519(encrypted2, ed25519Keys, encryption.DefaultDecryptOptions())
	if err != nil {
		t.Fatalf("Failed to decrypt second encryption: %v", err)
	}

	if string(decrypted1) != string(data) {
		t.Error("First decryption failed")
	}

	if string(decrypted2) != string(data) {
		t.Error("Second decryption failed")
	}
}

func TestEd25519EphemeralKeyGeneration(t *testing.T) {
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	data := []byte("test ephemeral key generation")
	opts := encryption.DefaultEncryptOptions()

	// Generate multiple encryptions to test ephemeral key generation
	ephemeralKeys := make(map[string]bool)
	numTests := 10

	for i := 0; i < numTests; i++ {
		encrypted, err := EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt iteration %d: %v", i, err)
		}

		// Check ephemeral key length (should be 32 bytes for X25519)
		if len(encrypted.EncryptedKey) != 32 {
			t.Errorf("Expected ephemeral key length 32, got %d", len(encrypted.EncryptedKey))
		}

		// Check for uniqueness
		keyStr := string(encrypted.EncryptedKey)
		if ephemeralKeys[keyStr] {
			t.Error("Ephemeral key collision detected - keys should be unique")
		}
		ephemeralKeys[keyStr] = true

		// Verify decryption works
		decrypted, err := DecryptWithEd25519(encrypted, ed25519Keys, encryption.DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt iteration %d: %v", i, err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decryption failed for iteration %d", i)
		}
	}

	// Verify we got unique ephemeral keys
	if len(ephemeralKeys) != numTests {
		t.Errorf("Expected %d unique ephemeral keys, got %d", numTests, len(ephemeralKeys))
	}
}

func TestEd25519CrossKeyDecryption(t *testing.T) {
	// Test that data encrypted with one Ed25519 key cannot be decrypted with another
	key1, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate first Ed25519 key pair: %v", err)
	}

	key2, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second Ed25519 key pair: %v", err)
	}

	data := []byte("test cross-key decryption protection")
	opts := encryption.DefaultEncryptOptions()

	// Encrypt with key1
	encrypted, err := EncryptWithEd25519(data, key1, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt with key1: %v", err)
	}

	// Try to decrypt with key2 (should fail)
	_, err = DecryptWithEd25519(encrypted, key2, encryption.DefaultDecryptOptions())
	if err == nil {
		t.Error("Expected error when decrypting with wrong key pair")
	}

	// Verify key1 can still decrypt correctly
	decrypted, err := DecryptWithEd25519(encrypted, key1, encryption.DefaultDecryptOptions())
	if err != nil {
		t.Fatalf("Failed to decrypt with correct key: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Error("Decryption with correct key failed")
	}
}
