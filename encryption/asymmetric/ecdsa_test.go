package asymmetric

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEncryptWithECDSA(t *testing.T) {
	testCases := []struct {
		name  string
		curve algo.ECDSACurve
	}{
		{"P256", algo.P256},
		{"P384", algo.P384},
		{"P521", algo.P521},
	}

	opts := encryption.DefaultEncryptOptions()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ecdsaKeys, err := algo.GenerateECDSAKeyPair(tc.curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair for %s: %v", tc.name, err)
			}

			data := []byte("test data for ECDSA encryption")

			encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt with ECDSA %s: %v", tc.name, err)
			}

			if encrypted == nil {
				t.Fatal("Encrypted data is nil")
			}
			if encrypted.Algorithm != encryption.AlgorithmECDH {
				t.Errorf("Expected algorithm %s, got %s", encryption.AlgorithmECDH, encrypted.Algorithm)
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
		})
	}
}

func TestEncryptWithECDSALargeData(t *testing.T) {
	ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	opts := encryption.DefaultEncryptOptions()

	// Test with various data sizes
	testSizes := []int{0, 1, 100, 1024, 10240, 100000}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size%d", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt %d bytes: %v", size, err)
			}

			if encrypted == nil {
				t.Fatal("Encrypted data is nil")
			}

			// ECDSA with AES-GCM can handle any size data
			if len(encrypted.Data) == 0 && size > 0 {
				t.Error("Encrypted data should not be empty for non-empty input")
			}
		})
	}
}

func TestDecryptWithECDSA(t *testing.T) {
	testCases := []struct {
		name  string
		curve algo.ECDSACurve
	}{
		{"P256", algo.P256},
		{"P384", algo.P384},
		{"P521", algo.P521},
	}

	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ecdsaKeys, err := algo.GenerateECDSAKeyPair(tc.curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair for %s: %v", tc.name, err)
			}

			data := []byte("test data for ECDSA decryption")

			encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			decrypted, err := DecryptWithECDSA(encrypted, ecdsaKeys, decryptOpts)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			if string(decrypted) != string(data) {
				t.Errorf("Decrypted data doesn't match. Expected: %s, Got: %s", string(data), string(decrypted))
			}
		})
	}
}

func TestDecryptWithECDSAErrorCases(t *testing.T) {
	ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()
	data := []byte("test data")

	t.Run("WrongAlgorithm", func(t *testing.T) {
		encrypted := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmRSAOAEP, // Wrong algorithm
			Data:      []byte("encrypted"),
		}

		_, err := DecryptWithECDSA(encrypted, ecdsaKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for wrong algorithm")
		}
		if !strings.Contains(err.Error(), "expected ECDH") {
			t.Errorf("Expected algorithm error, got: %v", err)
		}
	})

	t.Run("InvalidEphemeralKey", func(t *testing.T) {
		encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the ephemeral key
		encrypted.EncryptedKey = []byte("invalid ephemeral key")

		_, err = DecryptWithECDSA(encrypted, ecdsaKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for invalid ephemeral key")
		}
	})

	t.Run("CorruptedData", func(t *testing.T) {
		encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the encrypted data
		encrypted.Data[0] ^= 0xFF

		_, err = DecryptWithECDSA(encrypted, ecdsaKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for corrupted data")
		}
	})

	t.Run("CorruptedTag", func(t *testing.T) {
		encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the authentication tag
		encrypted.Tag[0] ^= 0xFF

		_, err = DecryptWithECDSA(encrypted, ecdsaKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for corrupted authentication tag")
		}
	})

	t.Run("WrongKeyPair", func(t *testing.T) {
		// Generate different key pair
		wrongKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate wrong ECDSA key pair: %v", err)
		}

		encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		_, err = DecryptWithECDSA(encrypted, wrongKeys, decryptOpts)
		if err == nil {
			t.Error("Expected error for wrong key pair")
		}
	})

	t.Run("InvalidDecryptOptions", func(t *testing.T) {
		encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		invalidDecryptOpts := encryption.DecryptOptions{
			MaxAge: -1, // Invalid negative max age
		}

		_, err = DecryptWithECDSA(encrypted, ecdsaKeys, invalidDecryptOpts)
		if err == nil {
			t.Error("Expected error for invalid decrypt options")
		}
	})
}

func TestECDSARoundTrip(t *testing.T) {
	curves := []struct {
		name  string
		curve algo.ECDSACurve
	}{
		{"P256", algo.P256},
		{"P384", algo.P384},
		{"P521", algo.P521},
	}

	dataSizes := []int{0, 1, 16, 100, 1024, 10000}
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	for _, c := range curves {
		for _, size := range dataSizes {
			t.Run(fmt.Sprintf("%s_Size%d", c.name, size), func(t *testing.T) {
				ecdsaKeys, err := algo.GenerateECDSAKeyPair(c.curve)
				if err != nil {
					t.Fatalf("Failed to generate ECDSA key pair: %v", err)
				}

				data := make([]byte, size)
				for i := range data {
					data[i] = byte(i % 256)
				}

				encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				decrypted, err := DecryptWithECDSA(encrypted, ecdsaKeys, decryptOpts)
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
}

func TestECDSAWithMetadata(t *testing.T) {
	ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	data := []byte("test data with metadata")
	opts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmECDH,
		Format:    encryption.FormatCMS,
		Metadata: map[string]interface{}{
			"curve":      "P256",
			"test_value": 123,
			"nested": map[string]interface{}{
				"inner": "value",
			},
		},
	}

	encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if encrypted.Metadata == nil {
		t.Error("Metadata should be preserved")
	}

	if val, ok := encrypted.Metadata["curve"]; !ok || val != "P256" {
		t.Error("String metadata not preserved correctly")
	}

	if val, ok := encrypted.Metadata["test_value"]; !ok || val != 123 {
		t.Error("Numeric metadata not preserved correctly")
	}

	if nested, ok := encrypted.Metadata["nested"].(map[string]interface{}); !ok {
		t.Error("Nested metadata not preserved correctly")
	} else {
		if inner, ok := nested["inner"]; !ok || inner != "value" {
			t.Error("Nested inner value not preserved correctly")
		}
	}
}

func TestECDSAKeyConversion(t *testing.T) {
	// Test that ECDSA keys can be properly converted to ECDH
	// P224 is not supported by crypto/ecdh
	curves := []algo.ECDSACurve{algo.P256, algo.P384, algo.P521}

	for _, curve := range curves {
		t.Run(fmt.Sprintf("Curve%v", curve), func(t *testing.T) {
			ecdsaKeys, err := algo.GenerateECDSAKeyPair(curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			// Test that the key conversion works in encryption
			data := []byte("test key conversion")
			opts := encryption.DefaultEncryptOptions()

			encrypted, err := EncryptWithECDSA(data, ecdsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt (key conversion failed): %v", err)
			}

			// Verify ephemeral key is present and valid
			if len(encrypted.EncryptedKey) == 0 {
				t.Error("Ephemeral key should be present")
			}

			// Test decryption (which also requires key conversion)
			decrypted, err := DecryptWithECDSA(encrypted, ecdsaKeys, encryption.DefaultDecryptOptions())
			if err != nil {
				t.Fatalf("Failed to decrypt (key conversion failed): %v", err)
			}

			if string(decrypted) != string(data) {
				t.Error("Round-trip failed due to key conversion issues")
			}
		})
	}
}

func TestECDSAP224NotSupported(t *testing.T) {
	// Test that P224 curve is not supported due to crypto/ecdh limitations
	ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P224)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P224 key pair: %v", err)
	}

	data := []byte("test data")
	opts := encryption.DefaultEncryptOptions()

	_, err = EncryptWithECDSA(data, ecdsaKeys, opts)
	if err == nil {
		t.Error("Expected error for P224 curve (not supported by crypto/ecdh)")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("Expected unsupported curve error, got: %v", err)
	}
}

func TestECDSAInvalidOptions(t *testing.T) {
	ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	data := []byte("test data")

	t.Run("InvalidEncryptOptions", func(t *testing.T) {
		invalidOpts := encryption.EncryptOptions{
			Algorithm: "invalid_algorithm",
			Format:    encryption.FormatCMS,
		}

		_, err := EncryptWithECDSA(data, ecdsaKeys, invalidOpts)
		if err == nil {
			t.Error("Expected error for invalid encrypt options")
		}
	})
}
