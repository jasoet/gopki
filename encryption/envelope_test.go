package encryption

import (
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEnvelopeEncryptor(t *testing.T) {
	encryptor := NewEnvelopeEncryptor()
	data := []byte("Envelope encryption test data")

	t.Run("Single Recipient RSA", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted, err := encryptor.Encrypt(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if encrypted.Algorithm != AlgorithmEnvelope {
			t.Errorf("Expected envelope algorithm, got %s", encrypted.Algorithm)
		}

		if len(encrypted.Data) == 0 {
			t.Error("Expected encrypted data")
		}

		if len(encrypted.EncryptedKey) == 0 {
			t.Error("Expected encrypted key")
		}

		if len(encrypted.IV) == 0 {
			t.Error("Expected IV")
		}

		if len(encrypted.Tag) == 0 {
			t.Error("Expected tag")
		}

		decrypted, err := encryptor.Decrypt(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("Single Recipient ECDSA", func(t *testing.T) {
		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		encrypted, err := encryptor.Encrypt(data, ecdsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := encryptor.Decrypt(encrypted, ecdsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("Single Recipient Ed25519", func(t *testing.T) {
		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		encrypted, err := encryptor.Encrypt(data, ed25519Keys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := encryptor.Decrypt(encrypted, ed25519Keys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("EncryptForPublicKey", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted, err := encryptor.EncryptForPublicKey(data, &rsaKeys.PrivateKey.PublicKey, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt for public key: %v", err)
		}

		decrypted, err := encryptor.Decrypt(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Decrypted data doesn't match original")
		}
	})

	t.Run("Multiple Recipients", func(t *testing.T) {
		// Generate multiple key pairs
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		recipients := []any{
			&rsaKeys.PrivateKey.PublicKey,
			&ecdsaKeys.PrivateKey.PublicKey,
			ed25519Keys.PublicKey,
		}

		encrypted, err := encryptor.EncryptForMultipleRecipients(data, recipients, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt for multiple recipients: %v", err)
		}

		if len(encrypted.Recipients) != 3 {
			t.Errorf("Expected 3 recipients, got %d", len(encrypted.Recipients))
		}

		// Test decryption with each recipient
		decrypted1, err := encryptor.DecryptForRecipient(encrypted, rsaKeys, 0, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt for RSA recipient: %v", err)
		}

		if string(decrypted1) != string(data) {
			t.Error("RSA recipient decryption failed")
		}

		decrypted2, err := encryptor.DecryptForRecipient(encrypted, ecdsaKeys, 1, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt for ECDSA recipient: %v", err)
		}

		if string(decrypted2) != string(data) {
			t.Error("ECDSA recipient decryption failed")
		}

		decrypted3, err := encryptor.DecryptForRecipient(encrypted, ed25519Keys, 2, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt for Ed25519 recipient: %v", err)
		}

		if string(decrypted3) != string(data) {
			t.Error("Ed25519 recipient decryption failed")
		}
	})

	t.Run("No Recipients Error", func(t *testing.T) {
		recipients := []any{}

		_, err := encryptor.EncryptForMultipleRecipients(data, recipients, DefaultEncryptOptions())
		if err == nil {
			t.Error("Expected error for no recipients")
		}
	})

	t.Run("Invalid Recipient Index", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted, err := encryptor.Encrypt(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Add some fake recipients
		encrypted.Recipients = []*RecipientInfo{{}, {}}

		_, err = encryptor.DecryptForRecipient(encrypted, rsaKeys, 5, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for invalid recipient index")
		}

		_, err = encryptor.DecryptForRecipient(encrypted, rsaKeys, -1, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for negative recipient index")
		}
	})

	t.Run("Wrong Algorithm for Decryption", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted := &EncryptedData{
			Algorithm: AlgorithmRSAOAEP, // Wrong algorithm
			Data:      []byte("test"),
		}

		_, err = encryptor.Decrypt(encrypted, rsaKeys, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for wrong algorithm")
		}

		_, err = encryptor.DecryptForRecipient(encrypted, rsaKeys, 0, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for wrong algorithm in DecryptForRecipient")
		}
	})

	t.Run("Fallback to Single Recipient", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted, err := encryptor.Encrypt(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Clear recipients to test fallback
		encrypted.Recipients = nil

		decrypted, err := encryptor.DecryptForRecipient(encrypted, rsaKeys, 0, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with fallback: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Fallback decryption failed")
		}
	})

	t.Run("Include Certificate Option", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		opts := DefaultEncryptOptions()
		opts.IncludeCertificate = true

		encrypted, err := encryptor.Encrypt(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if len(encrypted.Recipients) == 0 {
			t.Error("Expected recipients to be set when IncludeCertificate is true")
		}
	})

	t.Run("DecryptWithPrivateKey Not Supported", func(t *testing.T) {
		encrypted := &EncryptedData{
			Algorithm: AlgorithmEnvelope,
			Data:      []byte("test"),
		}

		_, err := encryptor.DecryptWithPrivateKey(encrypted, nil, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for DecryptWithPrivateKey")
		}
	})

	t.Run("SupportedAlgorithms", func(t *testing.T) {
		algorithms := encryptor.SupportedAlgorithms()
		expected := []EncryptionAlgorithm{
			AlgorithmEnvelope,
			AlgorithmAESGCM,
			AlgorithmRSAOAEP,
			AlgorithmECDH,
			AlgorithmX25519,
		}

		if len(algorithms) != len(expected) {
			t.Errorf("Expected %d algorithms, got %d", len(algorithms), len(expected))
		}

		for _, alg := range expected {
			found := false
			for _, supported := range algorithms {
				if supported == alg {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Algorithm %s should be supported", alg)
			}
		}
	})
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getKeyType", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		if getKeyType(rsaKeys) != "RSA" {
			t.Errorf("Expected RSA key type, got %s", getKeyType(rsaKeys))
		}

		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		if getKeyType(ecdsaKeys) != "ECDSA" {
			t.Errorf("Expected ECDSA key type, got %s", getKeyType(ecdsaKeys))
		}

		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		if getKeyType(ed25519Keys) != "Ed25519" {
			t.Errorf("Expected Ed25519 key type, got %s", getKeyType(ed25519Keys))
		}

		if getKeyType("invalid") != "Unknown" {
			t.Error("Expected Unknown for invalid key type")
		}
	})

	t.Run("getPublicKeyType", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		if getPublicKeyType(&rsaKeys.PrivateKey.PublicKey) != "RSA" {
			t.Error("Expected RSA public key type")
		}

		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		if getPublicKeyType(&ecdsaKeys.PrivateKey.PublicKey) != "ECDSA" {
			t.Error("Expected ECDSA public key type")
		}

		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		if getPublicKeyType(ed25519Keys.PublicKey) != "Ed25519" {
			t.Error("Expected Ed25519 public key type")
		}

		if getPublicKeyType("invalid") != "Unknown" {
			t.Error("Expected Unknown for invalid public key type")
		}
	})
}
