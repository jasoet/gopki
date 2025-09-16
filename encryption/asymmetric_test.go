package encryption

import (
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestAsymmetricEncryptor(t *testing.T) {
	encryptor := NewAsymmetricEncryptor()
	data := []byte("Asymmetric encryption test data")

	t.Run("RSA-OAEP Encryption", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encrypted, err := encryptor.EncryptWithRSA(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with RSA: %v", err)
		}

		if encrypted.Algorithm != AlgorithmRSAOAEP {
			t.Errorf("Expected RSA-OAEP algorithm, got %s", encrypted.Algorithm)
		}

		decrypted, err := encryptor.DecryptWithRSA(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with RSA: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("RSA decrypted data doesn't match original")
		}
	})

	t.Run("ECDH Encryption", func(t *testing.T) {
		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmECDH,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encrypted, err := encryptor.EncryptWithECDSA(data, ecdsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with ECDSA: %v", err)
		}

		if encrypted.Algorithm != AlgorithmECDH {
			t.Errorf("Expected ECDH algorithm, got %s", encrypted.Algorithm)
		}

		if len(encrypted.IV) == 0 {
			t.Error("Expected IV to be set for ECDH encryption")
		}

		if len(encrypted.Tag) == 0 {
			t.Error("Expected tag to be set for ECDH encryption")
		}

		if len(encrypted.EncryptedKey) == 0 {
			t.Error("Expected ephemeral key to be set for ECDH encryption")
		}

		decrypted, err := encryptor.DecryptWithECDSA(encrypted, ecdsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with ECDSA: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("ECDSA decrypted data doesn't match original")
		}
	})

	t.Run("X25519 Encryption", func(t *testing.T) {
		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmX25519,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encrypted, err := encryptor.EncryptWithEd25519(data, ed25519Keys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt with Ed25519: %v", err)
		}

		if encrypted.Algorithm != AlgorithmX25519 {
			t.Errorf("Expected X25519 algorithm, got %s", encrypted.Algorithm)
		}

		if len(encrypted.IV) == 0 {
			t.Error("Expected IV to be set for X25519 encryption")
		}

		if len(encrypted.Tag) == 0 {
			t.Error("Expected tag to be set for X25519 encryption")
		}

		if len(encrypted.EncryptedKey) == 0 {
			t.Error("Expected ephemeral key to be set for X25519 encryption")
		}

		decrypted, err := encryptor.DecryptWithEd25519(encrypted, ed25519Keys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt with Ed25519: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Ed25519 decrypted data doesn't match original")
		}
	})

	t.Run("Generic Encrypt/Decrypt", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encrypted, err := encryptor.Encrypt(data, rsaKeys, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := encryptor.Decrypt(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Generic decrypted data doesn't match original")
		}
	})

	t.Run("EncryptForPublicKey RSA", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encrypted, err := encryptor.EncryptForPublicKey(data, &rsaKeys.PrivateKey.PublicKey, opts)
		if err != nil {
			t.Fatalf("Failed to encrypt for public key: %v", err)
		}

		decrypted, err := encryptor.Decrypt(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Error("Public key encrypted data doesn't match original")
		}
	})

	t.Run("Data Too Large for RSA", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Create data that's too large for RSA-OAEP
		largeData := make([]byte, 300) // 2048-bit RSA can only encrypt ~190 bytes with OAEP
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		_, err = encryptor.EncryptWithRSA(largeData, rsaKeys, opts)
		if err == nil {
			t.Error("Expected error for data too large for RSA encryption")
		}
	})

	t.Run("Unsupported Key Type", func(t *testing.T) {
		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		_, err := encryptor.Encrypt(data, "invalid", opts)
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})

	t.Run("Wrong Algorithm for Decryption", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted := &EncryptedData{
			Algorithm: AlgorithmECDH, // Wrong algorithm
			Data:      []byte("test"),
		}

		_, err = encryptor.DecryptWithRSA(encrypted, rsaKeys, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for wrong algorithm")
		}
	})

	t.Run("SupportedAlgorithms", func(t *testing.T) {
		algorithms := encryptor.SupportedAlgorithms()
		expected := []EncryptionAlgorithm{
			AlgorithmRSAOAEP,
			AlgorithmECDH,
			AlgorithmX25519,
		}

		if len(algorithms) != len(expected) {
			t.Errorf("Expected %d algorithms, got %d", len(expected), len(algorithms))
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

	t.Run("DecryptWithPrivateKey Not Supported", func(t *testing.T) {
		encrypted := &EncryptedData{
			Algorithm: AlgorithmRSAOAEP,
			Data:      []byte("test"),
		}

		_, err := encryptor.DecryptWithPrivateKey(encrypted, nil, DefaultDecryptOptions())
		if err == nil {
			t.Error("Expected error for DecryptWithPrivateKey")
		}
	})
}
