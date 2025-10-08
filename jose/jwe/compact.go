package jwe

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/envelope"
	"github.com/jasoet/gopki/jose/internal/encoding"
	"github.com/jasoet/gopki/keypair"
)

// Header represents JWE protected header
type Header struct {
	Algorithm        string `json:"alg"`           // Key encryption algorithm
	EncryptionMethod string `json:"enc"`           // Content encryption algorithm
	KeyID            string `json:"kid,omitempty"` // Key ID (optional)
}

// EncryptCompact encrypts data in JWE compact serialization format.
//
// Format: BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)
//
// This is a thin wrapper over GoPKI's envelope encryption that formats
// the output according to RFC 7516.
//
// Type parameter:
//   - K: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - plaintext: The data to encrypt (any size supported)
//   - recipient: The recipient's key pair (public key used for key encryption)
//   - keyAlg: Key encryption algorithm ("RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A256KW")
//   - encAlg: Content encryption algorithm ("A256GCM", "A192GCM", "A128GCM")
//   - keyID: Optional key identifier
//
// Returns:
//   - string: JWE compact serialization (5 parts separated by dots)
//   - error: Any error during encryption
//
// Example:
//
//	jweToken, err := jwe.EncryptCompact(
//	    plaintext,
//	    rsaKeys,
//	    "RSA-OAEP-256",
//	    "A256GCM",
//	    "key-1",
//	)
func EncryptCompact[K keypair.KeyPair](
	plaintext []byte,
	recipient K,
	keyAlg string,
	encAlg string,
	keyID string,
) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	// Create JWE header
	header := Header{
		Algorithm:        keyAlg,
		EncryptionMethod: encAlg,
		KeyID:            keyID,
	}

	// Encode header
	headerB64, err := encoding.EncodeJSON(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	// Use GoPKI envelope encryption (hybrid encryption: DEK + KEK)
	opts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmEnvelope,
		Format:    encryption.FormatCMS,
		Metadata:  make(map[string]interface{}),
	}

	encrypted, err := envelope.Encrypt(plaintext, recipient, opts)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// Extract components from envelope encryption
	// encrypted.Data = ciphertext
	// encrypted.IV = initialization vector
	// encrypted.Tag = authentication tag
	// encrypted.Recipients[0].EncryptedKey = encrypted DEK

	if len(encrypted.Recipients) == 0 {
		return "", fmt.Errorf("no recipients in encrypted data")
	}

	encryptedKey := encrypted.Recipients[0].EncryptedKey
	iv := encrypted.IV
	ciphertext := encrypted.Data
	tag := encrypted.Tag

	// Encode all components as Base64URL
	encKeyB64 := encoding.EncodeBytes(encryptedKey)
	ivB64 := encoding.EncodeBytes(iv)
	ciphertextB64 := encoding.EncodeBytes(ciphertext)
	tagB64 := encoding.EncodeBytes(tag)

	// Return JWE compact format: header.enckey.iv.ciphertext.tag
	return strings.Join([]string{
		headerB64,
		encKeyB64,
		ivB64,
		ciphertextB64,
		tagB64,
	}, "."), nil
}

// DecryptCompact decrypts JWE compact serialization format.
//
// Type parameter:
//   - K: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - jwe: The JWE compact serialization string
//   - recipient: The recipient's key pair (private key used for key decryption)
//
// Returns:
//   - []byte: The decrypted plaintext
//   - error: Any error during decryption
//
// Example:
//
//	plaintext, err := jwe.DecryptCompact(jweToken, rsaKeys)
func DecryptCompact[K keypair.KeyPair](jwe string, recipient K) ([]byte, error) {
	// Split into 5 parts
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, ErrInvalidJWEFormat
	}

	// Decode header
	headerBytes, err := encoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}

	// Decode all components
	encryptedKey, err := encoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted key encoding: %w", err)
	}

	iv, err := encoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid IV encoding: %w", err)
	}

	ciphertext, err := encoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	tag, err := encoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid tag encoding: %w", err)
	}

	// Reconstruct EncryptedData for GoPKI envelope decryption
	keyEncAlg, err := jweAlgToGoPKIAlg(header.Algorithm)
	if err != nil {
		return nil, err
	}

	encrypted := &encryption.EncryptedData{
		Algorithm: encryption.AlgorithmEnvelope,
		Format:    encryption.FormatCMS,
		Data:      ciphertext,
		IV:        iv,
		Tag:       tag,
		Recipients: []*encryption.RecipientInfo{
			{
				EncryptedKey:           encryptedKey,
				KeyEncryptionAlgorithm: keyEncAlg,
			},
		},
	}

	// Use GoPKI envelope decryption
	opts := encryption.DecryptOptions{
		ExpectedAlgorithm: encryption.AlgorithmEnvelope,
	}

	plaintext, err := envelope.Decrypt(encrypted, recipient, opts)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// jweAlgToGoPKIAlg converts JWE algorithm name to GoPKI algorithm
func jweAlgToGoPKIAlg(jweAlg string) (encryption.Algorithm, error) {
	switch jweAlg {
	case "RSA-OAEP", "RSA-OAEP-256":
		return encryption.AlgorithmRSAOAEP, nil
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		return encryption.AlgorithmECDH, nil
	case "dir":
		// Direct key agreement (symmetric)
		return encryption.AlgorithmAESGCM, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, jweAlg)
	}
}
