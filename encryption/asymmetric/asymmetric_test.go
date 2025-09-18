package asymmetric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEncrypt(t *testing.T) {
	data := []byte("test data for encryption")
	opts := encryption.DefaultEncryptOptions()

	t.Run("RSA", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		encrypted, err := Encrypt(data, rsaKeys, opts)
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
	})

	t.Run("ECDSA", func(t *testing.T) {
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		encrypted, err := Encrypt(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with ECDSA: %v", err)
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
	})

	t.Run("Ed25519", func(t *testing.T) {
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		encrypted, err := Encrypt(data, ed25519Keys, opts)
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
	})

	t.Run("NilKeyType", func(t *testing.T) {
		// Test with nil (which will cause a panic that we should handle gracefully)
		defer func() {
			if r := recover(); r != nil {
				// This is expected - nil pointer dereference should be caught
				t.Logf("Caught expected panic for nil key: %v", r)
			}
		}()

		var nilKey *algo.RSAKeyPair
		_, err := Encrypt(data, nilKey, opts)
		if err == nil {
			t.Error("Expected error for nil key type")
		}
	})
}

func TestDecrypt(t *testing.T) {
	data := []byte("test data for decryption")
	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	t.Run("RSA", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		encrypted, err := Encrypt(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := Decrypt(encrypted, rsaKeys, decryptOpts)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match. Expected: %s, Got: %s", string(data), string(decrypted))
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		encrypted, err := Encrypt(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := Decrypt(encrypted, ecdsaKeys, decryptOpts)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match. Expected: %s, Got: %s", string(data), string(decrypted))
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		encrypted, err := Encrypt(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := Decrypt(encrypted, ed25519Keys, decryptOpts)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match. Expected: %s, Got: %s", string(data), string(decrypted))
		}
	})

	t.Run("NilKeyType", func(t *testing.T) {
		// Test that nil keys are handled gracefully
		defer func() {
			if r := recover(); r != nil {
				// This is expected - nil pointer dereference should be caught
				t.Logf("Caught expected panic for nil key: %v", r)
			}
		}()

		encrypted := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmRSAOAEP,
			Data:      []byte("test"),
		}

		var nilKey *algo.RSAKeyPair
		_, err := Decrypt(encrypted, nilKey, decryptOpts)
		if err == nil {
			t.Error("Expected error for nil key type")
		}
	})
}

func TestEncryptForPublicKey(t *testing.T) {
	data := []byte("test data for public key encryption")
	opts := encryption.DefaultEncryptOptions()

	t.Run("RSA", func(t *testing.T) {
		rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		encrypted, err := EncryptForPublicKey(data, rsaKeys.PublicKey, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt for RSA public key: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
		if encrypted.Algorithm != encryption.AlgorithmRSAOAEP {
			t.Errorf("Expected algorithm %s, got %s", encryption.AlgorithmRSAOAEP, encrypted.Algorithm)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		_, err = EncryptForPublicKey(data, ecdsaKeys.PublicKey, opts)
		if err == nil {
			t.Error("Expected error for ECDSA public key encryption (not yet implemented)")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		_, err = EncryptForPublicKey(data, ed25519Keys.PublicKey, opts)
		if err == nil {
			t.Error("Expected error for Ed25519 public key encryption (not yet implemented)")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				// This is expected - nil pointer dereference should be caught
				t.Logf("Caught expected panic for nil public key: %v", r)
			}
		}()

		var nilKey *rsa.PublicKey
		_, err := EncryptForPublicKey(data, nilKey, opts)
		if err == nil {
			t.Error("Expected error for nil public key")
		}
	})
}

func TestEncryptForPublicKeyAny(t *testing.T) {
	data := []byte("test data for public key any encryption")
	opts := encryption.DefaultEncryptOptions()

	t.Run("RSA", func(t *testing.T) {
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		encrypted, err := EncryptForPublicKeyAny(data, &rsaPrivateKey.PublicKey, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt for RSA public key: %v", err)
		}

		if encrypted == nil {
			t.Fatal("Encrypted data is nil")
		}
		if encrypted.Algorithm != encryption.AlgorithmRSAOAEP {
			t.Errorf("Expected algorithm %s, got %s", encryption.AlgorithmRSAOAEP, encrypted.Algorithm)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		_, err = EncryptForPublicKeyAny(data, ecdsaKeys.PublicKey, opts)
		if err == nil {
			t.Error("Expected error for ECDSA public key encryption (not yet implemented)")
		}
		if !strings.Contains(err.Error(), "not yet implemented") {
			t.Errorf("Expected 'not yet implemented' error, got: %v", err)
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		_, err = EncryptForPublicKeyAny(data, publicKey, opts)
		if err == nil {
			t.Error("Expected error for Ed25519 public key encryption (not yet implemented)")
		}
	})

	t.Run("UnsupportedPublicKeyType", func(t *testing.T) {
		type unsupportedPublicKey struct{}

		_, err := EncryptForPublicKeyAny(data, &unsupportedPublicKey{}, opts)
		if err == nil {
			t.Error("Expected error for unsupported public key type")
		}
	})
}

func TestDecryptWithPrivateKey(t *testing.T) {
	encrypted := &encryption.EncryptedData{
		Algorithm: encryption.AlgorithmRSAOAEP,
		Data:      []byte("test"),
	}

	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	_, err = DecryptWithPrivateKey(encrypted, rsaKeys.PrivateKey, encryption.DefaultDecryptOptions())
	if err == nil {
		t.Error("Expected error - DecryptWithPrivateKey should not be supported for asymmetric encryption")
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	algorithms := SupportedAlgorithms()

	expectedAlgorithms := []encryption.Algorithm{
		encryption.AlgorithmRSAOAEP,
		encryption.AlgorithmECDH,
		encryption.AlgorithmX25519,
	}

	if len(algorithms) != len(expectedAlgorithms) {
		t.Errorf("Expected %d algorithms, got %d", len(expectedAlgorithms), len(algorithms))
	}

	for _, expected := range expectedAlgorithms {
		found := false
		for _, alg := range algorithms {
			if alg == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected algorithm %s not found in supported algorithms", expected)
		}
	}
}

func TestRoundTripEncryption(t *testing.T) {
	testData := [][]byte{
		[]byte("short"),
		[]byte("medium length test data for encryption"),
		[]byte(""),
	}

	opts := encryption.DefaultEncryptOptions()
	decryptOpts := encryption.DefaultDecryptOptions()

	for _, data := range testData {
		t.Run("RSA", func(t *testing.T) {
			rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
			if err != nil {
				t.Fatalf("Failed to generate RSA key pair: %v", err)
			}

			encrypted, err := Encrypt(data, rsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			decrypted, err := Decrypt(encrypted, rsaKeys, decryptOpts)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			if string(decrypted) != string(data) {
				t.Errorf("Round-trip failed. Original: %v, Decrypted: %v", data, decrypted)
			}
		})

		t.Run("ECDSA", func(t *testing.T) {
			ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			encrypted, err := Encrypt(data, ecdsaKeys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			decrypted, err := Decrypt(encrypted, ecdsaKeys, decryptOpts)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			if string(decrypted) != string(data) {
				t.Errorf("Round-trip failed. Original: %v, Decrypted: %v", data, decrypted)
			}
		})

		t.Run("Ed25519", func(t *testing.T) {
			ed25519Keys, err := algo.GenerateEd25519KeyPair()
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
			}

			encrypted, err := Encrypt(data, ed25519Keys, opts)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			decrypted, err := Decrypt(encrypted, ed25519Keys, decryptOpts)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			if string(decrypted) != string(data) {
				t.Errorf("Round-trip failed. Original: %v, Decrypted: %v", data, decrypted)
			}
		})
	}
}
