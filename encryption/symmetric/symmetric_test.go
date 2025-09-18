package symmetric

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jasoet/gopki/encryption"
	"github.com/stretchr/testify/assert"
)

func TestEncryptAESGCM(t *testing.T) {
	testData := []byte("test data for AES-GCM encryption")
	opts := encryption.DefaultEncryptOptions()

	t.Run("AES-128", func(t *testing.T) {
		key, err := GenerateAESKey(16)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmAESGCM, encrypted.Algorithm)
		assert.NotEmpty(t, encrypted.Data)
		assert.NotEmpty(t, encrypted.IV)
		assert.NotEmpty(t, encrypted.Tag)
		assert.Equal(t, 12, len(encrypted.IV))  // GCM nonce size
		assert.Equal(t, 16, len(encrypted.Tag)) // GCM tag size
	})

	t.Run("AES-192", func(t *testing.T) {
		key, err := GenerateAESKey(24)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmAESGCM, encrypted.Algorithm)
	})

	t.Run("AES-256", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmAESGCM, encrypted.Algorithm)
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		invalidKey := make([]byte, 15) // Invalid size

		encrypted, err := EncryptAESGCM(testData, invalidKey, opts)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
		assert.Contains(t, err.Error(), "invalid AES key size")
	})

	t.Run("Empty Data", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM([]byte{}, key, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Empty(t, encrypted.Data)
	})

	t.Run("Large Data", func(t *testing.T) {
		largeData := make([]byte, 1024*1024) // 1MB
		_, err := rand.Read(largeData)
		assert.NoError(t, err)

		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(largeData, key, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Len(t, encrypted.Data, len(largeData))
	})

	t.Run("With Metadata", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		opts := encryption.DefaultEncryptOptions()
		opts.Metadata = map[string]interface{}{
			"purpose": "testing",
			"algorithm": "AES-GCM",
		}

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted.Metadata)
		assert.Equal(t, "testing", encrypted.Metadata["purpose"])
		assert.Equal(t, "AES-GCM", encrypted.Metadata["algorithm"])
	})

	t.Run("Unique Nonces", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted1, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		encrypted2, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		// Same plaintext should produce different ciphertexts due to unique nonces
		assert.NotEqual(t, encrypted1.IV, encrypted2.IV)
		assert.NotEqual(t, encrypted1.Data, encrypted2.Data)
		assert.NotEqual(t, encrypted1.Tag, encrypted2.Tag)
	})
}

func TestDecryptAESGCM(t *testing.T) {
	testData := []byte("test data for AES-GCM decryption")
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	t.Run("AES-128 Round Trip", func(t *testing.T) {
		key, err := GenerateAESKey(16)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("AES-192 Round Trip", func(t *testing.T) {
		key, err := GenerateAESKey(24)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("AES-256 Round Trip", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("Wrong Algorithm", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmRSAOAEP,
			Data:      []byte("test"),
			IV:        make([]byte, 12),
			Tag:       make([]byte, 16),
		}

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "expected AES-GCM algorithm")
	})

	t.Run("Wrong Key", func(t *testing.T) {
		key1, err := GenerateAESKey(32)
		assert.NoError(t, err)
		key2, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key1, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, key2, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		invalidKey := make([]byte, 15)
		decrypted, err := DecryptAESGCM(encrypted, invalidKey, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "invalid AES key size")
	})

	t.Run("Tampered Ciphertext", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		// Tamper with ciphertext
		encrypted.Data[0] ^= 0x01

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("Tampered Tag", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		// Tamper with authentication tag
		encrypted.Tag[0] ^= 0x01

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("Tampered IV", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, opts)
		assert.NoError(t, err)

		// Tamper with IV/nonce
		encrypted.IV[0] ^= 0x01

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("Large Data Round Trip", func(t *testing.T) {
		largeData := make([]byte, 5*1024*1024) // 5MB
		_, err := rand.Read(largeData)
		assert.NoError(t, err)

		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(largeData, key, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(largeData, decrypted))
	})

	t.Run("Empty Data Round Trip", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM([]byte{}, key, opts)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, key, decryptOpts)
		assert.NoError(t, err)
		assert.Empty(t, decrypted)
	})
}

func TestGenerateAESKey(t *testing.T) {
	t.Run("AES-128", func(t *testing.T) {
		key, err := GenerateAESKey(16)
		assert.NoError(t, err)
		assert.Len(t, key, 16)
	})

	t.Run("AES-192", func(t *testing.T) {
		key, err := GenerateAESKey(24)
		assert.NoError(t, err)
		assert.Len(t, key, 24)
	})

	t.Run("AES-256", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("Invalid Key Sizes", func(t *testing.T) {
		invalidSizes := []int{8, 12, 15, 17, 20, 25, 31, 33, 64}
		for _, size := range invalidSizes {
			key, err := GenerateAESKey(size)
			assert.Error(t, err)
			assert.Nil(t, key)
			assert.Contains(t, err.Error(), "invalid AES key size")
		}
	})

	t.Run("Key Uniqueness", func(t *testing.T) {
		key1, err := GenerateAESKey(32)
		assert.NoError(t, err)

		key2, err := GenerateAESKey(32)
		assert.NoError(t, err)

		// Keys should be different
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Key Randomness", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		// Key should not be all zeros
		allZeros := make([]byte, 32)
		assert.NotEqual(t, allZeros, key)

		// Key should not be all 0xFF
		allFF := make([]byte, 32)
		for i := range allFF {
			allFF[i] = 0xFF
		}
		assert.NotEqual(t, allFF, key)
	})
}

func TestDeriveKeyFromPassword(t *testing.T) {
	password := "test-password-123"
	salt := []byte("test-salt-16-bytes-long")
	iterations := 100000

	t.Run("AES-128", func(t *testing.T) {
		key, err := DeriveKeyFromPassword(password, salt, 16, iterations)
		assert.NoError(t, err)
		assert.Len(t, key, 16)
	})

	t.Run("AES-192", func(t *testing.T) {
		key, err := DeriveKeyFromPassword(password, salt, 24, iterations)
		assert.NoError(t, err)
		assert.Len(t, key, 24)
	})

	t.Run("AES-256", func(t *testing.T) {
		key, err := DeriveKeyFromPassword(password, salt, 32, iterations)
		assert.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("Deterministic", func(t *testing.T) {
		key1, err := DeriveKeyFromPassword(password, salt, 32, iterations)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromPassword(password, salt, 32, iterations)
		assert.NoError(t, err)

		// Same inputs should produce same key
		assert.Equal(t, key1, key2)
	})

	t.Run("Different Passwords", func(t *testing.T) {
		key1, err := DeriveKeyFromPassword("password1", salt, 32, iterations)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromPassword("password2", salt, 32, iterations)
		assert.NoError(t, err)

		// Different passwords should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Different Salts", func(t *testing.T) {
		salt1 := []byte("salt1-16-bytes-long")
		salt2 := []byte("salt2-16-bytes-long")

		key1, err := DeriveKeyFromPassword(password, salt1, 32, iterations)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromPassword(password, salt2, 32, iterations)
		assert.NoError(t, err)

		// Different salts should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Different Iterations", func(t *testing.T) {
		key1, err := DeriveKeyFromPassword(password, salt, 32, 10000)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromPassword(password, salt, 32, 20000)
		assert.NoError(t, err)

		// Different iteration counts should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		key, err := DeriveKeyFromPassword(password, salt, 15, iterations)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "invalid AES key size")
	})

	t.Run("Salt Too Short", func(t *testing.T) {
		shortSalt := []byte("short")
		key, err := DeriveKeyFromPassword(password, shortSalt, 32, iterations)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "salt too short")
	})

	t.Run("Iterations Too Low", func(t *testing.T) {
		key, err := DeriveKeyFromPassword(password, salt, 32, 500)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "iteration count too low")
	})

	t.Run("Round Trip Encryption", func(t *testing.T) {
		testData := []byte("test data for password-derived encryption")

		key, err := DeriveKeyFromPassword(password, salt, 32, iterations)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, encryption.DefaultEncryptOptions())
		assert.NoError(t, err)

		// Derive the same key again
		derivedKey, err := DeriveKeyFromPassword(password, salt, 32, iterations)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, derivedKey, encryption.DefaultDecryptOptions())
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})
}

func TestDeriveKeyFromSharedSecret(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	assert.NoError(t, err)

	info := []byte("test-context-info")

	t.Run("AES-128", func(t *testing.T) {
		key, err := DeriveKeyFromSharedSecret(sharedSecret, info, 16)
		assert.NoError(t, err)
		assert.Len(t, key, 16)
	})

	t.Run("AES-192", func(t *testing.T) {
		key, err := DeriveKeyFromSharedSecret(sharedSecret, info, 24)
		assert.NoError(t, err)
		assert.Len(t, key, 24)
	})

	t.Run("AES-256", func(t *testing.T) {
		key, err := DeriveKeyFromSharedSecret(sharedSecret, info, 32)
		assert.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("Deterministic", func(t *testing.T) {
		key1, err := DeriveKeyFromSharedSecret(sharedSecret, info, 32)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromSharedSecret(sharedSecret, info, 32)
		assert.NoError(t, err)

		// Same inputs should produce same key
		assert.Equal(t, key1, key2)
	})

	t.Run("Different Shared Secrets", func(t *testing.T) {
		sharedSecret1 := make([]byte, 32)
		sharedSecret2 := make([]byte, 32)
		_, err := rand.Read(sharedSecret1)
		assert.NoError(t, err)
		_, err = rand.Read(sharedSecret2)
		assert.NoError(t, err)

		key1, err := DeriveKeyFromSharedSecret(sharedSecret1, info, 32)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromSharedSecret(sharedSecret2, info, 32)
		assert.NoError(t, err)

		// Different shared secrets should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Different Info", func(t *testing.T) {
		info1 := []byte("context1")
		info2 := []byte("context2")

		key1, err := DeriveKeyFromSharedSecret(sharedSecret, info1, 32)
		assert.NoError(t, err)

		key2, err := DeriveKeyFromSharedSecret(sharedSecret, info2, 32)
		assert.NoError(t, err)

		// Different info should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("No Info", func(t *testing.T) {
		key, err := DeriveKeyFromSharedSecret(sharedSecret, nil, 32)
		assert.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		key, err := DeriveKeyFromSharedSecret(sharedSecret, info, 15)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "invalid AES key size")
	})

	t.Run("Empty Shared Secret", func(t *testing.T) {
		key, err := DeriveKeyFromSharedSecret([]byte{}, info, 32)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "shared secret cannot be empty")
	})

	t.Run("Round Trip Encryption", func(t *testing.T) {
		testData := []byte("test data for shared secret encryption")

		key, err := DeriveKeyFromSharedSecret(sharedSecret, info, 32)
		assert.NoError(t, err)

		encrypted, err := EncryptAESGCM(testData, key, encryption.DefaultEncryptOptions())
		assert.NoError(t, err)

		// Derive the same key again
		derivedKey, err := DeriveKeyFromSharedSecret(sharedSecret, info, 32)
		assert.NoError(t, err)

		decrypted, err := DecryptAESGCM(encrypted, derivedKey, encryption.DefaultDecryptOptions())
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})
}

func TestGenerateSalt(t *testing.T) {
	t.Run("Minimum Size", func(t *testing.T) {
		salt, err := GenerateSalt(16)
		assert.NoError(t, err)
		assert.Len(t, salt, 16)
	})

	t.Run("Large Salt", func(t *testing.T) {
		salt, err := GenerateSalt(64)
		assert.NoError(t, err)
		assert.Len(t, salt, 64)
	})

	t.Run("Salt Uniqueness", func(t *testing.T) {
		salt1, err := GenerateSalt(16)
		assert.NoError(t, err)

		salt2, err := GenerateSalt(16)
		assert.NoError(t, err)

		// Salts should be different
		assert.NotEqual(t, salt1, salt2)
	})

	t.Run("Salt Randomness", func(t *testing.T) {
		salt, err := GenerateSalt(16)
		assert.NoError(t, err)

		// Salt should not be all zeros
		allZeros := make([]byte, 16)
		assert.NotEqual(t, allZeros, salt)
	})

	t.Run("Salt Too Small", func(t *testing.T) {
		salt, err := GenerateSalt(8)
		assert.Error(t, err)
		assert.Nil(t, salt)
		assert.Contains(t, err.Error(), "salt size too small")
	})
}

func TestQuickEncryptSymmetric(t *testing.T) {
	testData := []byte("test data for quick symmetric encryption")

	t.Run("Valid Encryption", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := QuickEncryptSymmetric(testData, key)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Equal(t, encryption.AlgorithmAESGCM, encrypted.Algorithm)
		assert.NotEmpty(t, encrypted.Data)
	})

	t.Run("Invalid Key", func(t *testing.T) {
		invalidKey := make([]byte, 15)

		encrypted, err := QuickEncryptSymmetric(testData, invalidKey)
		assert.Error(t, err)
		assert.Nil(t, encrypted)
	})
}

func TestQuickDecryptSymmetric(t *testing.T) {
	testData := []byte("test data for quick symmetric decryption")

	t.Run("Round Trip", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := QuickEncryptSymmetric(testData, key)
		assert.NoError(t, err)

		decrypted, err := QuickDecryptSymmetric(encrypted, key)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("Wrong Key", func(t *testing.T) {
		key1, err := GenerateAESKey(32)
		assert.NoError(t, err)
		key2, err := GenerateAESKey(32)
		assert.NoError(t, err)

		encrypted, err := QuickEncryptSymmetric(testData, key1)
		assert.NoError(t, err)

		decrypted, err := QuickDecryptSymmetric(encrypted, key2)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
	})
}

func TestSymmetricPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	key, err := GenerateAESKey(32)
	assert.NoError(t, err)

	// Test with different data sizes
	dataSizes := []int{
		1024,         // 1KB
		1024 * 1024,  // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range dataSizes {
		t.Run(fmt.Sprintf("Size%dB", size), func(t *testing.T) {
			data := make([]byte, size)
			_, err := rand.Read(data)
			assert.NoError(t, err)

			// Measure encryption
			encrypted, err := QuickEncryptSymmetric(data, key)
			assert.NoError(t, err)

			// Measure decryption
			decrypted, err := QuickDecryptSymmetric(encrypted, key)
			assert.NoError(t, err)

			assert.True(t, bytes.Equal(data, decrypted))
		})
	}
}