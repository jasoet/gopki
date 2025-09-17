package asymmetric

import (
	"strings"
	"testing"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEncryptWithRSA(t *testing.T) {
	rsaKeys, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	opts := encryption.DefaultEncryptOptions()

	t.Run("ValidData", func(t *testing.T) {
		data := []byte("test data for RSA encryption")

		encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with RSA: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
		if encrypted.Algorithm != encryption.AlgorithmRSAOAEP {
			t.Errorf("Expected algorithm %s, got %s", encryption.AlgorithmRSAOAEP, encrypted.Algorithm)
		}
		if len(encrypted.Data) == 0 {
			t.Error("Encrypted data is empty")
		}
		if encrypted.Format != opts.Format {
			t.Errorf("Expected format %s, got %s", opts.Format, encrypted.Format)
		}
		if encrypted.Timestamp.IsZero() {
			t.Error("Timestamp should be set")
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		data := []byte("")

		encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt empty data: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
		if len(encrypted.Data) == 0 {
			t.Error("Encrypted data should not be empty even for empty input")
		}
	})

	t.Run("LargeData", func(t *testing.T) {
		// RSA-OAEP with 2048-bit key can handle about 190 bytes max
		// Let's test with data that's too large
		largeData := make([]byte, 300) // Too large for RSA-2048
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		_, err := EncryptWithRSA(largeData, rsaKeys, opts)
		if err == nil {
			t.Error("Expected error for data too large for RSA")
		}
		if !strings.Contains(err.Error(), "data size") {
			t.Errorf("Expected data size error, got: %v", err)
		}
	})

	t.Run("MaxSizeData", func(t *testing.T) {
		// Test with data that's at the maximum size for RSA-2048
		// For 2048-bit RSA with OAEP-SHA256, max data size is key_size - 2*hash_size - 2
		// = 256 - 2*32 - 2 = 190 bytes
		maxData := make([]byte, 190)
		for i := range maxData {
			maxData[i] = byte(i % 256)
		}

		encrypted, err := EncryptWithRSA(maxData, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt max size data: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
	})

	t.Run("InvalidOptions", func(t *testing.T) {
		data := []byte("test data")
		invalidOpts := encryption.EncryptOptions{
			Algorithm: "invalid",
			Format:    encryption.FormatCMS,
		}

		_, err := EncryptWithRSA(data, rsaKeys, invalidOpts)
		if err == nil {
			t.Error("Expected error for invalid options")
		}
	})
}

func TestDecryptWithRSA(t *testing.T) {
	rsaKeys, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()
	data := []byte("test data for RSA decryption")

	t.Run("ValidDecryption", func(t *testing.T) {
		encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := DecryptWithRSA(encrypted, rsaKeys, decryptOpts)
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

		_, err := DecryptWithRSA(encrypted, rsaKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for wrong algorithm")
		}
		if !strings.Contains(err.Error(), "expected RSA-OAEP") {
			t.Errorf("Expected algorithm error, got: %v", err)
		}
	})

	t.Run("CorruptedData", func(t *testing.T) {
		encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the encrypted data
		encrypted.Data[0] ^= 0xFF

		_, err = DecryptWithRSA(encrypted, rsaKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for corrupted data")
		}
	})

	t.Run("WrongKeyPair", func(t *testing.T) {
		// Generate different key pair
		wrongKeys, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate wrong RSA key pair: %v", err)
		}

		encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		_, err = DecryptWithRSA(encrypted, wrongKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for wrong key pair")
		}
	})

	t.Run("InvalidDecryptOptions", func(t *testing.T) {
		encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		invalidDecryptOpts := encryption.DecryptOptions{
			MaxAge: -1, // Invalid negative max age
		}

		_, err = DecryptWithRSA(encrypted, rsaKeys, invalidDecryptOpts)
		if err == nil {
			t.Error("Expected error for invalid decrypt options")
		}
	})
}

func TestRSARoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		keySize  algo.KeySize
		dataSize int
	}{
		{"RSA2048_Small", 2048, 10},
		{"RSA2048_Medium", 2048, 100},
		{"RSA2048_Max", 2048, 190}, // Max for 2048-bit RSA
		{"RSA3072_Small", 3072, 10},
		{"RSA3072_Medium", 3072, 200},
		{"RSA3072_Max", 3072, 318}, // Max for 3072-bit RSA
	}

	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rsaKeys, err := algo.GenerateRSAKeyPair(tc.keySize)
			if err != nil {
				t.Fatalf("Failed to generate RSA %d key pair: %v", tc.keySize, err)
			}

			data := make([]byte, tc.dataSize)
			for i := range data {
				data[i] = byte(i % 256)
			}

			encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			decrypted, err := DecryptWithRSA(encrypted, rsaKeys, decryptOpts)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
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

func TestRSADataSizeLimits(t *testing.T) {
	testCases := []struct {
		name     string
		keySize  algo.KeySize
		maxBytes int
	}{
		{"RSA2048", 2048, 190},
		{"RSA3072", 3072, 318},
		{"RSA4096", 4096, 446},
	}

	opts := encryption.DefaultEncryptOptions()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rsaKeys, err := algo.GenerateRSAKeyPair(tc.keySize)
			if err != nil {
				t.Fatalf("Failed to generate RSA %d key pair: %v", tc.keySize, err)
			}

			// Test data at max size (should work)
			maxData := make([]byte, tc.maxBytes)
			_, err = EncryptWithRSA(maxData, rsaKeys, opts)
			if err != nil {
				t.Errorf("Failed to encrypt max size data (%d bytes): %v", tc.maxBytes, err)
			}

			// Test data over max size (should fail)
			overMaxData := make([]byte, tc.maxBytes+1)
			_, err = EncryptWithRSA(overMaxData, rsaKeys, opts)
			if err == nil {
				t.Errorf("Expected error for over-max size data (%d bytes)", tc.maxBytes+1)
			}
		})
	}
}

func TestRSAWithMetadata(t *testing.T) {
	rsaKeys, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	data := []byte("test data with metadata")
	opts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmRSAOAEP,
		Format:    encryption.FormatCMS,
		Metadata: map[string]interface{}{
			"test_key": "test_value",
			"number":   42,
		},
	}

	encrypted, err := EncryptWithRSA(data, rsaKeys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if encrypted.Metadata == nil {
		t.Error("Metadata should be preserved")
	}

	if val, ok := encrypted.Metadata["test_key"]; !ok || val != "test_value" {
		t.Error("Metadata not preserved correctly")
	}

	if val, ok := encrypted.Metadata["number"]; !ok || val != 42 {
		t.Error("Numeric metadata not preserved correctly")
	}
}
