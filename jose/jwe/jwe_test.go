package jwe

import (
	"testing"

	"github.com/jasoet/gopki/encryption"
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

func TestDecryptCompactErrors(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	t.Run("Too few parts", func(t *testing.T) {
		_, err := DecryptCompact("header.enckey.iv", keyPair)
		assert.ErrorIs(t, err, ErrInvalidJWEFormat)
	})

	t.Run("Too many parts", func(t *testing.T) {
		_, err := DecryptCompact("a.b.c.d.e.f", keyPair)
		assert.ErrorIs(t, err, ErrInvalidJWEFormat)
	})

	t.Run("Invalid base64 in header", func(t *testing.T) {
		_, err := DecryptCompact("!!!invalid!!!.b.c.d.e", keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid JSON in header", func(t *testing.T) {
		invalidHeader := "eyBpbnZhbGlkIGpzb24=" // base64 of "{ invalid json"
		_, err := DecryptCompact(invalidHeader+".b.c.d.e", keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid base64 in encrypted key", func(t *testing.T) {
		// Valid header but invalid encrypted key
		header := "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0" // {"alg":"RSA-OAEP-256","enc":"A256GCM"}
		_, err := DecryptCompact(header+".!!!invalid!!!.c.d.e", keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid base64 in IV", func(t *testing.T) {
		header := "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
		encKey := "AQAB" // valid base64
		_, err := DecryptCompact(header+"."+encKey+".!!!invalid!!!.d.e", keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid base64 in ciphertext", func(t *testing.T) {
		header := "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
		encKey := "AQAB"
		iv := "AQAB"
		_, err := DecryptCompact(header+"."+encKey+"."+iv+".!!!invalid!!!.e", keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid base64 in tag", func(t *testing.T) {
		header := "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
		encKey := "AQAB"
		iv := "AQAB"
		ciphertext := "AQAB"
		_, err := DecryptCompact(header+"."+encKey+"."+iv+"."+ciphertext+".!!!invalid!!!", keyPair)
		assert.Error(t, err)
	})
}

func TestDecryptJSONErrors(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	t.Run("Empty recipients", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Recipients: []JSONRecipient{},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.ErrorIs(t, err, ErrNoRecipients)
	})

	t.Run("Invalid protected header", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected: "!!!invalid!!!",
			Recipients: []JSONRecipient{
				{EncryptedKey: "AQAB"},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid JSON in protected header", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected: "eyBpbnZhbGlkIGpzb24=", // base64 of "{ invalid json"
			Recipients: []JSONRecipient{
				{EncryptedKey: "AQAB"},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid IV", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected: "eyJlbmMiOiJBMjU2R0NNIn0", // {"enc":"A256GCM"}
			IV:        "!!!invalid!!!",
			Recipients: []JSONRecipient{
				{EncryptedKey: "AQAB"},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid ciphertext", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0",
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "!!!invalid!!!",
			Recipients: []JSONRecipient{
				{EncryptedKey: "AQAB"},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid tag", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0",
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "AQAB",
			Tag:        "!!!invalid!!!",
			Recipients: []JSONRecipient{
				{EncryptedKey: "AQAB"},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid encrypted key encoding", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0",
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "AQAB",
			Tag:        "AQAB",
			Recipients: []JSONRecipient{
				{
					Header:       map[string]interface{}{"alg": "RSA-OAEP-256"},
					EncryptedKey: "!!!invalid base64!!!",
				},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Missing alg in recipient header", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0",
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "AQAB",
			Tag:        "AQAB",
			Recipients: []JSONRecipient{
				{
					Header:       map[string]interface{}{}, // Missing "alg"
					EncryptedKey: "AQAB",
				},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Non-string alg in recipient header", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0",
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "AQAB",
			Tag:        "AQAB",
			Recipients: []JSONRecipient{
				{
					Header:       map[string]interface{}{"alg": 123}, // Not a string
					EncryptedKey: "AQAB",
				},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("Invalid algorithm in recipient header", func(t *testing.T) {
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0",
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "AQAB",
			Tag:        "AQAB",
			Recipients: []JSONRecipient{
				{
					Header:       map[string]interface{}{"alg": "UNKNOWN-ALG"},
					EncryptedKey: "AQAB",
				},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
	})

	t.Run("All recipients fail - returns error", func(t *testing.T) {
		// Create a JWE with invalid recipient that will fail decryption
		jweJSON := &JSONSerialization{
			Protected:  "eyJlbmMiOiJBMjU2R0NNIn0", // No padding for base64url
			IV:         "AQABAQABAQABAQABAQAB",
			Ciphertext: "AQAB",
			Tag:        "AQAB",
			Recipients: []JSONRecipient{
				{
					Header:       map[string]interface{}{"alg": "RSA-OAEP-256"},
					EncryptedKey: "AQAB", // Valid base64 but wrong encrypted key
				},
			},
		}
		_, err := DecryptJSON(jweJSON, keyPair)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decryption failed")
	})
}

func TestUnmarshalJSONErrors(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		_, err := UnmarshalJSON([]byte("{ invalid json"))
		assert.Error(t, err)
	})

	t.Run("Missing recipients", func(t *testing.T) {
		_, err := UnmarshalJSON([]byte(`{"iv":"abc","ciphertext":"def","tag":"ghi"}`))
		assert.Error(t, err)
	})

	t.Run("Empty recipients array", func(t *testing.T) {
		_, err := UnmarshalJSON([]byte(`{"recipients":[],"iv":"abc","ciphertext":"def","tag":"ghi"}`))
		assert.Error(t, err)
	})

	t.Run("Missing ciphertext", func(t *testing.T) {
		_, err := UnmarshalJSON([]byte(`{"recipients":[{"encrypted_key":"abc"}],"iv":"abc","tag":"ghi"}`))
		assert.Error(t, err)
	})
}

func TestJweAlgConversion(t *testing.T) {
	tests := []struct {
		name    string
		jweAlg  string
		want    encryption.Algorithm
		wantErr bool
	}{
		{"RSA-OAEP", "RSA-OAEP", encryption.AlgorithmRSAOAEP, false},
		{"RSA-OAEP-256", "RSA-OAEP-256", encryption.AlgorithmRSAOAEP, false},
		{"ECDH-ES", "ECDH-ES", encryption.AlgorithmECDH, false},
		{"ECDH-ES+A128KW", "ECDH-ES+A128KW", encryption.AlgorithmECDH, false},
		{"dir", "dir", encryption.AlgorithmAESGCM, false},
		{"Invalid", "INVALID-ALG", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jweAlgToGoPKIAlg(tt.jweAlg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestEncryptCompactDifferentKeySizes(t *testing.T) {
	t.Run("RSA 3072", func(t *testing.T) {
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize3072)
		require.NoError(t, err)

		plaintext := []byte("Test with RSA 3072")
		encrypted, err := EncryptCompact(plaintext, keyPair, "RSA-OAEP-256", "A256GCM", "test-3072")
		require.NoError(t, err)

		decrypted, err := DecryptCompact(encrypted, keyPair)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("RSA 4096", func(t *testing.T) {
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize4096)
		require.NoError(t, err)

		plaintext := []byte("Test with RSA 4096")
		encrypted, err := EncryptCompact(plaintext, keyPair, "RSA-OAEP-256", "A256GCM", "test-4096")
		require.NoError(t, err)

		decrypted, err := DecryptCompact(encrypted, keyPair)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestJSONMultiRecipientDifferentKeys(t *testing.T) {
	plaintext := []byte("Multi-recipient with different key sizes")

	rsa2048, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsa3072, _ := algo.GenerateRSAKeyPair(algo.KeySize3072)
	rsa4096, _ := algo.GenerateRSAKeyPair(algo.KeySize4096)

	recipients := []keypair.GenericPublicKey{
		rsa2048.PublicKey,
		rsa3072.PublicKey,
		rsa4096.PublicKey,
	}

	keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256"}
	keyIDs := []string{"2048-key", "3072-key", "4096-key"}

	jweJSON, err := EncryptJSON(plaintext, recipients, "A256GCM", keyAlgs, keyIDs)
	require.NoError(t, err)
	assert.Len(t, jweJSON.Recipients, 3)

	// Each recipient should decrypt successfully
	decrypted1, err := DecryptJSON(jweJSON, rsa2048)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted1)

	decrypted2, err := DecryptJSON(jweJSON, rsa3072)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)

	decrypted3, err := DecryptJSON(jweJSON, rsa4096)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted3)
}
