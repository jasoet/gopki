//go:build compatibility

package bao_test

import (
	"bytes"
	"testing"

	"github.com/jasoet/gopki/bao/pki"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/asymmetric"
)

func TestEncryption_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("RSA_OAEP_Encryption", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Key_GoPKI_Encrypt_Decrypt", testRSAOAEPBaoKeyGoPKI)
	})
}

// testRSAOAEPBaoKeyGoPKI tests RSA-OAEP encryption with Bao-generated keys.
func testRSAOAEPBaoKeyGoPKI(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao (exported)
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &pki.GenerateKeyOptions{
		KeyName: "encryption-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get key pair for GoPKI use
	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Test data
	plaintext := []byte("Secret message to encrypt with Bao RSA key")

	// Encrypt with GoPKI
	encryptOpts := encryption.DefaultEncryptOptions()
	encrypted, err := asymmetric.EncryptWithRSA(plaintext, keyPair, encryptOpts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with GoPKI
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := asymmetric.DecryptWithRSA(encrypted, keyPair, decryptOpts)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}

	t.Logf("✓ Successfully encrypted and decrypted with Bao RSA key using GoPKI")
}
