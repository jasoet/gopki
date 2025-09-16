package encryption

import (
	"fmt"
	"testing"
)

func TestSymmetricEncryptor(t *testing.T) {
	encryptor := NewSymmetricEncryptor()
	data := []byte("Symmetric encryption test data")

	t.Run("AES-GCM Encryption", func(t *testing.T) {
		// Generate a 256-bit AES key
		key, err := GenerateAESKey(32)
		if err != nil {
			t.Fatalf("Failed to generate AES key: %v", err)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmAESGCM,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encrypted, err := encryptor.EncryptAESGCM(data, key, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with AES-GCM: %v", err)
		}

		if encrypted.Algorithm != AlgorithmAESGCM {
			t.Errorf("Expected AES-GCM algorithm, got %s", encrypted.Algorithm)
		}

		if len(encrypted.IV) == 0 {
			t.Error("Expected IV to be set")
		}

		if len(encrypted.Tag) == 0 {
			t.Error("Expected tag to be set")
		}

		decrypted, err := encryptor.DecryptAESGCM(encrypted, key, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with AES-GCM: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("AES-GCM decrypted data doesn't match original")
		}
	})

	t.Run("Different Key Sizes", func(t *testing.T) {
		keySizes := []int{16, 24, 32} // AES-128, AES-192, AES-256

		for _, keySize := range keySizes {
			t.Run(fmt.Sprintf("AES-%d", keySize*8), func(t *testing.T) {
				key, err := GenerateAESKey(keySize)
				if err != nil {
					t.Fatalf("Failed to generate %d-byte AES key: %v", keySize, err)
				}

				if len(key) != keySize {
					t.Errorf("Expected key size %d, got %d", keySize, len(key))
				}

				opts := EncryptOptions{
					Algorithm: AlgorithmAESGCM,
					Format:    FormatCMS,
					Metadata:  make(map[string]interface{}),
				}

				encrypted, err := encryptor.EncryptAESGCM(data, key, opts)
				if err != nil {
					t.Fatalf("Failed to encrypt with %d-byte key: %v", keySize, err)
				}

				decrypted, err := encryptor.DecryptAESGCM(encrypted, key, DefaultDecryptOptions())
				if err != nil {
					t.Fatalf("Failed to decrypt with %d-byte key: %v", keySize, err)
				}

				if string(decrypted) != string(data) {
					t.Errorf("Decryption with %d-byte key failed", keySize)
				}
			})
		}
	})

	t.Run("Invalid Key Sizes", func(t *testing.T) {
		invalidSizes := []int{8, 15, 20, 40}

		for _, size := range invalidSizes {
			_, err := GenerateAESKey(size)
			if err == nil {
				t.Errorf("Expected error for invalid key size %d", size)
			}
		}
	})

	t.Run("Wrong Key Size for Encryption", func(t *testing.T) {
		invalidKey := []byte("tooshort")

		opts := EncryptOptions{
			Algorithm: AlgorithmAESGCM,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		_, err := encryptor.EncryptAESGCM(data, invalidKey, opts)
		if err == nil {
			t.Error("Expected error for invalid key size")
		}
	})

	t.Run("Wrong Algorithm for Decryption", func(t *testing.T) {
		key, err := GenerateAESKey(32)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		encrypted := &EncryptedData{
			Algorithm: AlgorithmRSAOAEP, // Wrong algorithm
			Data:      []byte("test"),
			IV:        make([]byte, 12),
			Tag:       make([]byte, 16),
		}

		_, err = encryptor.DecryptAESGCM(encrypted, key, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for wrong algorithm")
		}
	})

	t.Run("Encrypt Interface Methods", func(t *testing.T) {
		// These methods should return errors for symmetric encryption
		_, err := encryptor.Encrypt(data, nil, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for Encrypt method")
		}

		_, err = encryptor.Decrypt(nil, nil, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for Decrypt method")
		}

		_, err = encryptor.EncryptForPublicKey(data, nil, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for EncryptForPublicKey method")
		}

		_, err = encryptor.EncryptWithCertificate(data, nil, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for EncryptWithCertificate method")
		}

		_, err = encryptor.DecryptWithPrivateKey(nil, nil, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for DecryptWithPrivateKey method")
		}
	})

	t.Run("SupportedAlgorithms", func(t *testing.T) {
		algorithms := encryptor.SupportedAlgorithms()
		if len(algorithms) != 1 || algorithms[0] != AlgorithmAESGCM {
			t.Error("Expected only AES-GCM algorithm to be supported")
		}
	})
}

func TestKeyDerivation(t *testing.T) {
	t.Run("DeriveAESKey", func(t *testing.T) {
		sharedSecret := []byte("shared secret for key derivation")

		key1 := deriveAESKey(sharedSecret)
		key2 := deriveAESKey(sharedSecret)

		if len(key1) != 32 {
			t.Errorf("Expected 32-byte key, got %d", len(key1))
		}

		// Same input should produce same output
		if string(key1) != string(key2) {
			t.Error("Key derivation should be deterministic")
		}

		// Different input should produce different output
		key3 := deriveAESKey([]byte("different secret"))
		if string(key1) == string(key3) {
			t.Error("Different secrets should produce different keys")
		}
	})

	t.Run("DeriveKeyFromPassword", func(t *testing.T) {
		password := []byte("test password")
		salt, err := GenerateSalt(16)
		if err != nil {
			t.Fatalf("Failed to generate salt: %v", err)
		}

		key, err := DeriveKeyFromPassword(password, salt, 10000, 32)
		if err != nil {
			t.Fatalf("Failed to derive key from password: %v", err)
		}

		if len(key) != 32 {
			t.Errorf("Expected 32-byte key, got %d", len(key))
		}

		// Same inputs should produce same key
		key2, err := DeriveKeyFromPassword(password, salt, 10000, 32)
		if err != nil {
			t.Fatalf("Failed to derive key second time: %v", err)
		}

		if string(key) != string(key2) {
			t.Error("Key derivation should be deterministic")
		}

		// Different salt should produce different key
		salt2, _ := GenerateSalt(16)
		key3, err := DeriveKeyFromPassword(password, salt2, 10000, 32)
		if err != nil {
			t.Fatalf("Failed to derive key with different salt: %v", err)
		}

		if string(key) == string(key3) {
			t.Error("Different salts should produce different keys")
		}
	})

	t.Run("Invalid Password Derivation Parameters", func(t *testing.T) {
		password := []byte("test")
		salt := []byte("salt")

		// Invalid key size
		_, err := DeriveKeyFromPassword(password, salt, 10000, 15)
		if err == nil {
			t.Error("Expected error for invalid key size")
		}

		// Invalid iteration count
		_, err = DeriveKeyFromPassword(password, salt, 100, 32)
		if err == nil {
			t.Error("Expected error for low iteration count")
		}

		// Invalid salt size
		_, err = DeriveKeyFromPassword(password, []byte("short"), 10000, 32)
		if err == nil {
			t.Error("Expected error for short salt")
		}
	})

	t.Run("GenerateSalt", func(t *testing.T) {
		salt1, err := GenerateSalt(16)
		if err != nil {
			t.Fatalf("Failed to generate salt: %v", err)
		}

		if len(salt1) != 16 {
			t.Errorf("Expected 16-byte salt, got %d", len(salt1))
		}

		salt2, err := GenerateSalt(16)
		if err != nil {
			t.Fatalf("Failed to generate second salt: %v", err)
		}

		// Two salts should be different
		if string(salt1) == string(salt2) {
			t.Error("Generated salts should be different")
		}

		// Invalid salt size
		_, err = GenerateSalt(8)
		if err == nil {
			t.Error("Expected error for small salt size")
		}
	})
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("encryptAESGCM", func(t *testing.T) {
		data := []byte("test data")
		key := make([]byte, 32)

		encryptedData, iv, tag, err := encryptAESGCM(data, key)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if len(iv) == 0 {
			t.Error("Expected IV")
		}

		if len(tag) == 0 {
			t.Error("Expected tag")
		}

		// Test decryption
		decrypted, err := decryptAESGCM(encryptedData, key, iv, tag)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("encryptAESGCM with wrong key size", func(t *testing.T) {
		data := []byte("test data")
		key := make([]byte, 16) // Wrong size

		_, _, _, err := encryptAESGCM(data, key)
		if err == nil {
			t.Error("Expected error for wrong key size")
		}
	})

	t.Run("decryptAESGCM with wrong key size", func(t *testing.T) {
		data := []byte("test data")
		key := make([]byte, 16) // Wrong size
		iv := make([]byte, 12)
		tag := make([]byte, 16)

		_, err := decryptAESGCM(data, key, iv, tag)
		if err == nil {
			t.Error("Expected error for wrong key size")
		}
	})

	t.Run("decryptAESGCM with wrong IV size", func(t *testing.T) {
		data := []byte("test data")
		key := make([]byte, 32)
		iv := make([]byte, 10) // Wrong size
		tag := make([]byte, 16)

		_, err := decryptAESGCM(data, key, iv, tag)
		if err == nil {
			t.Error("Expected error for wrong IV size")
		}
	})
}
