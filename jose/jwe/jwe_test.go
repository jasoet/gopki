package jwe

import (
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompactRSAEncryptDecrypt(t *testing.T) {
	// Generate RSA key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	plaintext := []byte("Hello, JWE! This is a test message.")

	// Encrypt
	jweToken, err := EncryptCompact(
		plaintext,
		keyPair,
		"RSA-OAEP-256",
		"A256GCM",
		"test-key-1",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, jweToken)

	// Verify format (5 parts)
	assert.Equal(t, 5, len(splitJWE(jweToken)))

	// Decrypt
	decrypted, err := DecryptCompact(jweToken, keyPair)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCompactECDSAEncryptDecrypt(t *testing.T) {
	// TODO: ECDSA encryption requires ephemeral key handling
	// which needs additional implementation. Skip for Phase 3 MVP.
	t.Skip("ECDH-ES requires ephemeral key handling - implement in future version")

	// Generate ECDSA key pair
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	require.NoError(t, err)

	plaintext := []byte("ECDSA encryption test")

	// Encrypt
	jweToken, err := EncryptCompact(
		plaintext,
		keyPair,
		"ECDH-ES",
		"A256GCM",
		"ec-key-1",
	)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := DecryptCompact(jweToken, keyPair)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestJSONMultiRecipient(t *testing.T) {
	plaintext := []byte("Multi-recipient test message")

	// Generate multiple key pairs
	rsaKeys1, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	rsaKeys2, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	rsaKeys3, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	recipients := []keypair.GenericPublicKey{
		rsaKeys1.PublicKey,
		rsaKeys2.PublicKey,
		rsaKeys3.PublicKey,
	}

	keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256"}
	keyIDs := []string{"alice", "bob", "carol"}

	// Encrypt for all three recipients
	jweJSON, err := EncryptJSON(plaintext, recipients, "A256GCM", keyAlgs, keyIDs)
	require.NoError(t, err)
	assert.Len(t, jweJSON.Recipients, 3)

	// Each recipient should be able to decrypt
	decrypted1, err := DecryptJSON(jweJSON, rsaKeys1)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted1)

	decrypted2, err := DecryptJSON(jweJSON, rsaKeys2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)

	decrypted3, err := DecryptJSON(jweJSON, rsaKeys3)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted3)
}

func TestJSONMarshalUnmarshal(t *testing.T) {
	plaintext := []byte("JSON marshal test")

	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	require.NoError(t, err)

	recipients := []keypair.GenericPublicKey{keyPair.PublicKey}
	keyAlgs := []string{"RSA-OAEP-256"}
	keyIDs := []string{"test-key"}

	// Encrypt
	jweJSON, err := EncryptJSON(plaintext, recipients, "A256GCM", keyAlgs, keyIDs)
	require.NoError(t, err)

	// Marshal
	jsonBytes, err := jweJSON.Marshal()
	require.NoError(t, err)

	// Unmarshal
	parsed, err := UnmarshalJSON(jsonBytes)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := DecryptJSON(parsed, keyPair)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestErrorCases(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	t.Run("Empty plaintext", func(t *testing.T) {
		_, err := EncryptCompact([]byte{}, keyPair, "RSA-OAEP-256", "A256GCM", "")
		assert.Error(t, err)
	})

	t.Run("Invalid JWE format", func(t *testing.T) {
		_, err := DecryptCompact("invalid.jwe.format", keyPair)
		assert.ErrorIs(t, err, ErrInvalidJWEFormat)
	})

	t.Run("No recipients", func(t *testing.T) {
		_, err := EncryptJSON([]byte("test"), []keypair.GenericPublicKey{}, "A256GCM", []string{}, nil)
		assert.ErrorIs(t, err, ErrNoRecipients)
	})

	t.Run("Mismatched keyAlgs length", func(t *testing.T) {
		recipients := []keypair.GenericPublicKey{keyPair.PublicKey}
		keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP"}
		_, err := EncryptJSON([]byte("test"), recipients, "A256GCM", keyAlgs, nil)
		assert.Error(t, err)
	})
}

// Helper function to split JWE into parts
func splitJWE(jwe string) []string {
	parts := make([]string, 0)
	current := ""
	for _, ch := range jwe {
		if ch == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
