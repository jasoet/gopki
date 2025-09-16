package encryption

import (
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestTypeSafeAPI(t *testing.T) {
	data := []byte("Hello, Type Safety!")

	t.Run("Type-Safe RSA Encryption", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Test EncryptData with generic constraints
		encrypted, err := EncryptData(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		// Test DecryptData with generic constraints
		decrypted, err := DecryptData(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt data: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	t.Run("Type-Safe Public Key Encryption", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Test EncryptForPublicKey with generic constraints
		publicKey := &rsaKeys.PrivateKey.PublicKey
		encrypted, err := EncryptForPublicKey(data, publicKey, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt for public key: %v", err)
		}

		// Test decryption
		decrypted, err := DecryptData(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt data: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	t.Run("Type-Safe Asymmetric Encryption Functions", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Test EncryptAsymmetric wrapper
		encrypted, err := EncryptAsymmetric(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt with asymmetric wrapper: %v", err)
		}

		// Test DecryptAsymmetric wrapper
		decrypted, err := DecryptAsymmetric(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with asymmetric wrapper: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	t.Run("Type-Safe Envelope Encryption Functions", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Test EncryptEnvelope wrapper
		encrypted, err := EncryptEnvelope(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt with envelope wrapper: %v", err)
		}

		// Test DecryptEnvelope wrapper
		decrypted, err := DecryptEnvelope(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with envelope wrapper: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	t.Run("Type-Safe Symmetric Encryption Functions", func(t *testing.T) {
		// Generate AES key
		key, err := GenerateAESKey(32)
		if err != nil {
			t.Fatalf("Failed to generate AES key: %v", err)
		}

		// Test EncryptSymmetricTyped wrapper
		encrypted, err := EncryptSymmetricTyped(data, key, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt with symmetric wrapper: %v", err)
		}

		// Test DecryptSymmetricTyped wrapper
		decrypted, err := DecryptSymmetricTyped(encrypted, key, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with symmetric wrapper: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	t.Run("Quick Functions", func(t *testing.T) {
		// Generate RSA key pair
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Test QuickEncrypt/QuickDecrypt
		encrypted, err := QuickEncrypt(data, rsaKeys)
		if err != nil {
			t.Fatalf("Failed to quick encrypt: %v", err)
		}

		decrypted, err := QuickDecrypt(encrypted, rsaKeys)
		if err != nil {
			t.Fatalf("Failed to quick decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}

		// Test symmetric quick functions
		key, err := GenerateAESKey(32)
		if err != nil {
			t.Fatalf("Failed to generate AES key: %v", err)
		}

		symEncrypted, err := QuickEncryptSymmetric(data, key)
		if err != nil {
			t.Fatalf("Failed to quick encrypt symmetric: %v", err)
		}

		symDecrypted, err := QuickDecryptSymmetric(symEncrypted, key)
		if err != nil {
			t.Fatalf("Failed to quick decrypt symmetric: %v", err)
		}

		if string(symDecrypted) != string(data) {
			t.Errorf("Symmetric decrypted data doesn't match original")
		}
	})
}
