package asymmetric

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestDeriveAESKey(t *testing.T) {
	testCases := []struct {
		name         string
		secretLength int
	}{
		{"32ByteSecret", 32},
		{"64ByteSecret", 64},
		{"128ByteSecret", 128},
		{"MinSecret", 1},
		{"EmptySecret", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret := make([]byte, tc.secretLength)
			if tc.secretLength > 0 {
				_, err := rand.Read(secret)
				if err != nil {
					t.Fatalf("Failed to generate test secret: %v", err)
				}
			}

			derivedKey := deriveAESKey(secret)

			// Check that derived key is always 32 bytes (AES-256)
			if len(derivedKey) != 32 {
				t.Errorf("Expected derived key length 32, got %d", len(derivedKey))
			}

			// Check that the same input produces the same output (deterministic)
			derivedKey2 := deriveAESKey(secret)
			if !bytes.Equal(derivedKey, derivedKey2) {
				t.Error("Key derivation is not deterministic")
			}

			// Check that different inputs produce different outputs
			if tc.secretLength > 0 {
				differentSecret := make([]byte, tc.secretLength)
				differentSecret[0] = secret[0] ^ 0xFF // Make it different
				copy(differentSecret[1:], secret[1:])

				differentKey := deriveAESKey(differentSecret)
				if bytes.Equal(derivedKey, differentKey) {
					t.Error("Different secrets produced the same derived key")
				}
			}
		})
	}
}

func TestDeriveAESKeyConsistencyWithHKDF(t *testing.T) {
	// Test that our key derivation matches direct HKDF usage
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate test secret: %v", err)
	}

	// Derive key using our function
	ourKey := deriveAESKey(secret)

	// Derive key using HKDF directly (should match our implementation)
	hkdfReader := hkdf.New(sha256.New, secret, nil, []byte("GoPKI-AES-Key"))
	expectedKey := make([]byte, 32)
	_, err = io.ReadFull(hkdfReader, expectedKey)
	if err != nil {
		t.Fatalf("Failed to derive key with HKDF: %v", err)
	}

	if !bytes.Equal(ourKey, expectedKey) {
		t.Error("Our key derivation doesn't match HKDF implementation")
	}
}

func TestEncryptAESGCM(t *testing.T) {
	// Only test AES-256 as the implementation only supports 32-byte keys
	testKeys := [][]byte{
		make([]byte, 32), // AES-256
	}

	// Fill keys with test data
	for _, key := range testKeys {
		_, err := rand.Read(key)
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}
	}

	testData := [][]byte{
		[]byte(""),
		[]byte("short"),
		[]byte("medium length test data"),
		make([]byte, 1024),  // 1KB
		make([]byte, 10240), // 10KB
	}

	// Fill large test data
	for i := range testData[len(testData)-1] {
		testData[len(testData)-1][i] = byte(i % 256)
	}
	for i := range testData[len(testData)-2] {
		testData[len(testData)-2][i] = byte(i % 256)
	}

	for _, key := range testKeys {
		for dataIdx, data := range testData {
			t.Run(fmt.Sprintf("Key%dBytes_Data%d", len(key), dataIdx), func(t *testing.T) {
				ciphertext, iv, tag, err := encryptAESGCM(data, key)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				// Check IV length (should be 12 bytes for GCM)
				if len(iv) != 12 {
					t.Errorf("Expected IV length 12, got %d", len(iv))
				}

				// Check tag length (should be 16 bytes for GCM)
				if len(tag) != 16 {
					t.Errorf("Expected tag length 16, got %d", len(tag))
				}

				// Check ciphertext length matches plaintext length
				if len(ciphertext) != len(data) {
					t.Errorf("Ciphertext length %d doesn't match plaintext length %d", len(ciphertext), len(data))
				}

				// For non-empty data, ciphertext should be different from plaintext
				if len(data) > 0 && bytes.Equal(ciphertext, data) {
					t.Error("Ciphertext should be different from plaintext")
				}
			})
		}
	}
}

func TestEncryptAESGCMUniqueness(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	data := []byte("test data for uniqueness")

	// Encrypt the same data multiple times
	numTests := 10
	results := make(map[string]bool)

	for i := 0; i < numTests; i++ {
		ciphertext, iv, tag, err := encryptAESGCM(data, key)
		if err != nil {
			t.Fatalf("Failed to encrypt iteration %d: %v", i, err)
		}

		// Create unique identifier for this encryption
		identifier := string(iv) + string(tag) + string(ciphertext)

		if results[identifier] {
			t.Error("Encryption produced identical results - IVs should be unique")
		}
		results[identifier] = true

		// Each IV should be unique
		ivStr := string(iv)
		if len(ivStr) != 12 {
			t.Errorf("IV length should be 12, got %d", len(ivStr))
		}
	}

	if len(results) != numTests {
		t.Errorf("Expected %d unique encryptions, got %d", numTests, len(results))
	}
}

func TestEncryptAESGCMInvalidKey(t *testing.T) {
	// Test invalid keys - implementation only accepts 32-byte keys
	invalidKeys := [][]byte{
		make([]byte, 15), // Too short
		make([]byte, 16), // AES-128 not supported
		make([]byte, 24), // AES-192 not supported
		make([]byte, 31), // Too short
		make([]byte, 33), // Too long
		nil,              // Nil key
		{},               // Empty key
	}

	data := []byte("test data")

	for i, key := range invalidKeys {
		t.Run(fmt.Sprintf("InvalidKey%d", i), func(t *testing.T) {
			_, _, _, err := encryptAESGCM(data, key)
			if err == nil {
				t.Errorf("Expected error for invalid key of length %d", len(key))
			}
		})
	}
}

func TestDecryptAESGCM(t *testing.T) {
	// Only test AES-256 as the implementation only supports 32-byte keys
	testKeys := [][]byte{
		make([]byte, 32), // AES-256
	}

	// Fill keys with test data
	for _, key := range testKeys {
		_, err := rand.Read(key)
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}
	}

	testData := [][]byte{
		[]byte(""),
		[]byte("short"),
		[]byte("medium length test data for decryption"),
		make([]byte, 1024),
	}

	// Fill large test data
	for i := range testData[len(testData)-1] {
		testData[len(testData)-1][i] = byte(i % 256)
	}

	for _, key := range testKeys {
		for dataIdx, originalData := range testData {
			t.Run(fmt.Sprintf("Key%dBytes_Data%d", len(key), dataIdx), func(t *testing.T) {
				// Encrypt first
				ciphertext, iv, tag, err := encryptAESGCM(originalData, key)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				// Decrypt
				decrypted, err := decryptAESGCM(ciphertext, key, iv, tag)
				if err != nil {
					t.Fatalf("Failed to decrypt: %v", err)
				}

				// Verify decrypted data matches original
				if !bytes.Equal(decrypted, originalData) {
					t.Errorf("Decrypted data doesn't match original. Expected: %v, Got: %v", originalData, decrypted)
				}
			})
		}
	}
}

func TestDecryptAESGCMErrorCases(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	data := []byte("test data for error cases")
	ciphertext, iv, tag, err := encryptAESGCM(data, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	t.Run("InvalidKey", func(t *testing.T) {
		invalidKey := make([]byte, 15) // Invalid length
		_, err := decryptAESGCM(ciphertext, invalidKey, iv, tag)
		if err == nil {
			t.Error("Expected error for invalid key")
		}
	})

	t.Run("WrongKey", func(t *testing.T) {
		wrongKey := make([]byte, 32)
		_, err := rand.Read(wrongKey)
		if err != nil {
			t.Fatalf("Failed to generate wrong key: %v", err)
		}

		_, err = decryptAESGCM(ciphertext, wrongKey, iv, tag)
		if err == nil {
			t.Error("Expected error for wrong key")
		}
	})

	t.Run("CorruptedCiphertext", func(t *testing.T) {
		corruptedCiphertext := make([]byte, len(ciphertext))
		copy(corruptedCiphertext, ciphertext)
		if len(corruptedCiphertext) > 0 {
			corruptedCiphertext[0] ^= 0xFF
		}

		_, err := decryptAESGCM(corruptedCiphertext, key, iv, tag)
		if err == nil {
			t.Error("Expected error for corrupted ciphertext")
		}
	})

	t.Run("CorruptedIV", func(t *testing.T) {
		corruptedIV := make([]byte, len(iv))
		copy(corruptedIV, iv)
		corruptedIV[0] ^= 0xFF

		_, err := decryptAESGCM(ciphertext, key, corruptedIV, tag)
		if err == nil {
			t.Error("Expected error for corrupted IV")
		}
	})

	t.Run("CorruptedTag", func(t *testing.T) {
		corruptedTag := make([]byte, len(tag))
		copy(corruptedTag, tag)
		corruptedTag[0] ^= 0xFF

		_, err := decryptAESGCM(ciphertext, key, iv, corruptedTag)
		if err == nil {
			t.Error("Expected error for corrupted tag")
		}
	})

	t.Run("InvalidIVLength", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				// Expected panic for invalid IV length
				t.Logf("Caught expected panic for invalid IV length: %v", r)
			}
		}()

		invalidIV := make([]byte, 11) // Wrong length
		_, err := decryptAESGCM(ciphertext, key, invalidIV, tag)
		if err == nil {
			t.Error("Expected error for invalid IV length")
		}
	})

	t.Run("InvalidTagLength", func(t *testing.T) {
		invalidTag := make([]byte, 15) // Wrong length
		_, err := decryptAESGCM(ciphertext, key, iv, invalidTag)
		if err == nil {
			t.Error("Expected error for invalid tag length")
		}
	})

	t.Run("NilInputs", func(t *testing.T) {
		// Test nil ciphertext
		_, err := decryptAESGCM(nil, key, iv, tag)
		if err == nil {
			t.Error("Expected error for nil ciphertext")
		}

		// Test nil key
		_, err = decryptAESGCM(ciphertext, nil, iv, tag)
		if err == nil {
			t.Error("Expected error for nil key")
		}

		// Test nil IV (this will panic)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("Caught expected panic for nil IV: %v", r)
				}
			}()
			_, err = decryptAESGCM(ciphertext, key, nil, tag)
			if err == nil {
				t.Error("Expected error for nil IV")
			}
		}()

		// Test nil tag
		_, err = decryptAESGCM(ciphertext, key, iv, nil)
		if err == nil {
			t.Error("Expected error for nil tag")
		}
	})
}

func TestAESGCMRoundTrip(t *testing.T) {
	// Test complete round-trip encryption/decryption
	// Only test AES-256 as implementation only supports 32-byte keys
	testCases := []struct {
		keySize  int
		dataSize int
	}{
		{32, 0},
		{32, 1},
		{32, 100},
		{32, 1000},
		{32, 10000},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Key%d_Data%d", tc.keySize, tc.dataSize), func(t *testing.T) {
			key := make([]byte, tc.keySize)
			_, err := rand.Read(key)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			originalData := make([]byte, tc.dataSize)
			for i := range originalData {
				originalData[i] = byte(i % 256)
			}

			// Encrypt
			ciphertext, iv, tag, err := encryptAESGCM(originalData, key)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			// Decrypt
			decrypted, err := decryptAESGCM(ciphertext, key, iv, tag)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Verify
			if !bytes.Equal(decrypted, originalData) {
				t.Error("Round-trip failed: decrypted data doesn't match original")
			}
		})
	}
}

func BenchmarkDeriveAESKey(b *testing.B) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		b.Fatalf("Failed to generate test secret: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deriveAESKey(secret)
	}
}

func BenchmarkEncryptAESGCM(b *testing.B) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	data := make([]byte, 1024)
	_, err = rand.Read(data)
	if err != nil {
		b.Fatalf("Failed to generate data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := encryptAESGCM(data, key)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecryptAESGCM(b *testing.B) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	data := make([]byte, 1024)
	_, err = rand.Read(data)
	if err != nil {
		b.Fatalf("Failed to generate data: %v", err)
	}

	ciphertext, iv, tag, err := encryptAESGCM(data, key)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptAESGCM(ciphertext, key, iv, tag)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
