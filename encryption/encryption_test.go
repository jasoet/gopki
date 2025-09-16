package encryption

import (
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEncryptionBasics(t *testing.T) {
	data := []byte("Hello, World! This is a test message for encryption.")

	// Test with RSA
	t.Run("RSA Encryption", func(t *testing.T) {
		rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		encrypted, err := EncryptData(data, rsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		if encrypted.Algorithm != AlgorithmEnvelope {
			t.Errorf("Expected envelope algorithm, got %s", encrypted.Algorithm)
		}

		decrypted, err := DecryptData(encrypted, rsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt data: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	// Test with ECDSA
	t.Run("ECDSA Encryption", func(t *testing.T) {
		ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}

		encrypted, err := EncryptData(data, ecdsaKeys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		decrypted, err := DecryptData(encrypted, ecdsaKeys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt data: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})

	// Test with Ed25519
	t.Run("Ed25519 Encryption", func(t *testing.T) {
		ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}

		encrypted, err := EncryptData(data, ed25519Keys, DefaultEncryptOptions())
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		decrypted, err := DecryptData(encrypted, ed25519Keys, DefaultDecryptOptions())
		if err != nil {
			t.Fatalf("Failed to decrypt data: %v", err)
		}

		if string(decrypted) != string(data) {
			t.Errorf("Decrypted data doesn't match original")
		}
	})
}

func TestQuickEncryptDecrypt(t *testing.T) {
	data := []byte("Quick encryption test")

	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	encrypted, err := QuickEncrypt(data, rsaKeys)
	if err != nil {
		t.Fatalf("Failed to quick encrypt: %v", err)
	}

	decrypted, err := QuickDecrypt(encrypted, rsaKeys)
	if err != nil {
		t.Fatalf("Failed to quick decrypt: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Errorf("Quick decrypted data doesn't match original")
	}
}

func TestEncryptForPublicKey(t *testing.T) {
	data := []byte("Public key encryption test")

	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Encrypt for public key only
	encrypted, err := EncryptForPublicKey(data, &rsaKeys.PrivateKey.PublicKey, DefaultEncryptOptions())
	if err != nil {
		t.Fatalf("Failed to encrypt for public key: %v", err)
	}

	// Decrypt with full key pair
	decrypted, err := DecryptData(encrypted, rsaKeys, DefaultDecryptOptions())
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Errorf("Decrypted data doesn't match original")
	}
}

func TestMultipleRecipients(t *testing.T) {
	data := []byte("Multi-recipient encryption test")

	// Generate multiple key pairs
	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA keys: %v", err)
	}

	// Use envelope encryptor directly for mixed key types
	envelope := NewEnvelopeEncryptor()
	recipients := []any{
		&rsaKeys.PrivateKey.PublicKey,
		&ecdsaKeys.PrivateKey.PublicKey,
	}

	encrypted, err := envelope.EncryptForMultipleRecipients(data, recipients, DefaultEncryptOptions())
	if err != nil {
		t.Fatalf("Failed to encrypt for multiple recipients: %v", err)
	}

	// Test decryption with first recipient (RSA)
	decrypted1, err := DecryptForRecipient(encrypted, rsaKeys, 0, DefaultDecryptOptions())
	if err != nil {
		t.Fatalf("Failed to decrypt for first recipient: %v", err)
	}

	if string(decrypted1) != string(data) {
		t.Errorf("First recipient decryption failed")
	}

	// Test decryption with second recipient (ECDSA)
	decrypted2, err := DecryptForRecipient(encrypted, ecdsaKeys, 1, DefaultDecryptOptions())
	if err != nil {
		t.Fatalf("Failed to decrypt for second recipient: %v", err)
	}

	if string(decrypted2) != string(data) {
		t.Errorf("Second recipient decryption failed")
	}
}

func TestValidateKeyPairForEncryption(t *testing.T) {
	// Test valid RSA key pair
	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	if err := ValidateKeyPairForEncryption(rsaKeys); err != nil {
		t.Errorf("RSA key pair validation failed: %v", err)
	}

	// Test valid ECDSA key pair
	ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA keys: %v", err)
	}

	if err := ValidateKeyPairForEncryption(ecdsaKeys); err != nil {
		t.Errorf("ECDSA key pair validation failed: %v", err)
	}

	// Test valid Ed25519 key pair
	ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	if err := ValidateKeyPairForEncryption(ed25519Keys); err != nil {
		t.Errorf("Ed25519 key pair validation failed: %v", err)
	}

	// Test nil key pair - we need to use a concrete type
	var nilRSAKeys *algo.RSAKeyPair
	if err := ValidateKeyPairForEncryption(nilRSAKeys); err == nil {
		t.Error("Expected error for nil key pair")
	}
}

func TestGetRecommendedAlgorithm(t *testing.T) {
	rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	alg := GetRecommendedAlgorithm(rsaKeys)
	if alg != AlgorithmEnvelope {
		t.Errorf("Expected envelope algorithm recommendation, got %s", alg)
	}
}

func TestEstimateEncryptedSize(t *testing.T) {
	dataSize := 1000

	tests := []struct {
		algorithm EncryptionAlgorithm
		minSize   int
	}{
		{AlgorithmRSAOAEP, 250},
		{AlgorithmECDH, 1050},
		{AlgorithmX25519, 1050},
		{AlgorithmAESGCM, 1020},
		{AlgorithmEnvelope, 1250},
	}

	for _, test := range tests {
		size := EstimateEncryptedSize(dataSize, test.algorithm)
		if size < test.minSize {
			t.Errorf("Estimated size for %s too small: got %d, expected at least %d", test.algorithm, size, test.minSize)
		}
	}
}

func TestIsAlgorithmSupported(t *testing.T) {
	supportedAlgorithms := []EncryptionAlgorithm{
		AlgorithmRSAOAEP,
		AlgorithmECDH,
		AlgorithmX25519,
		AlgorithmAESGCM,
		AlgorithmEnvelope,
	}

	for _, alg := range supportedAlgorithms {
		if !IsAlgorithmSupported(alg) {
			t.Errorf("Algorithm %s should be supported", alg)
		}
	}

	if IsAlgorithmSupported("INVALID") {
		t.Error("Invalid algorithm should not be supported")
	}
}

func TestDefaultOptions(t *testing.T) {
	encOpts := DefaultEncryptOptions()
	if encOpts.Algorithm != AlgorithmEnvelope {
		t.Errorf("Default encrypt algorithm should be envelope, got %s", encOpts.Algorithm)
	}
	if encOpts.Format != FormatRaw {
		t.Errorf("Default format should be raw, got %s", encOpts.Format)
	}

	decOpts := DefaultDecryptOptions()
	if decOpts.MaxAge != 24*time.Hour {
		t.Errorf("Default max age should be 24 hours, got %v", decOpts.MaxAge)
	}
	if decOpts.SkipExpirationCheck {
		t.Error("Default should not skip expiration check")
	}
}

func TestValidateOptions(t *testing.T) {
	// Valid encrypt options
	validEncOpts := EncryptOptions{
		Algorithm: AlgorithmEnvelope,
		Format:    FormatRaw,
		Metadata:  make(map[string]interface{}),
	}
	if err := ValidateEncryptOptions(validEncOpts); err != nil {
		t.Errorf("Valid encrypt options should pass validation: %v", err)
	}

	// Invalid encrypt options
	invalidEncOpts := EncryptOptions{
		Algorithm: "INVALID",
		Format:    FormatRaw,
	}
	if err := ValidateEncryptOptions(invalidEncOpts); err == nil {
		t.Error("Invalid encrypt options should fail validation")
	}

	// Valid decrypt options
	validDecOpts := DecryptOptions{
		MaxAge: time.Hour,
	}
	if err := ValidateDecryptOptions(validDecOpts); err != nil {
		t.Errorf("Valid decrypt options should pass validation: %v", err)
	}

	// Invalid decrypt options
	invalidDecOpts := DecryptOptions{
		MaxAge: -time.Hour,
	}
	if err := ValidateDecryptOptions(invalidDecOpts); err == nil {
		t.Error("Invalid decrypt options should fail validation")
	}
}
