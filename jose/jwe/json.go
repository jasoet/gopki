package jwe

import (
	"encoding/json"
	"fmt"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/envelope"
	"github.com/jasoet/gopki/jose/internal/encoding"
	"github.com/jasoet/gopki/keypair"
)

// JSONSerialization represents JWE in JSON serialization format.
// This format supports multiple recipients.
//
// Example:
//
//	{
//	  "protected": "eyJlbmMiOiJBMjU2R0NNIn0",
//	  "unprotected": {"jku": "https://example.com/keys"},
//	  "recipients": [
//	    {
//	      "header": {"alg": "RSA-OAEP", "kid": "2011-04-29"},
//	      "encrypted_key": "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94..."
//	    }
//	  ],
//	  "iv": "AxY8DCtDaGlsbGljb3RoZQ",
//	  "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
//	  "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
//	}
type JSONSerialization struct {
	// Protected header (Base64URL-encoded)
	Protected string `json:"protected,omitempty"`

	// Unprotected header parameters
	Unprotected map[string]interface{} `json:"unprotected,omitempty"`

	// Recipients (one or more)
	Recipients []JSONRecipient `json:"recipients"`

	// Initialization vector (Base64URL-encoded)
	IV string `json:"iv"`

	// Ciphertext (Base64URL-encoded)
	Ciphertext string `json:"ciphertext"`

	// Authentication tag (Base64URL-encoded)
	Tag string `json:"tag"`
}

// JSONRecipient represents a single recipient in JSON serialization
type JSONRecipient struct {
	// Per-recipient header parameters
	Header map[string]interface{} `json:"header,omitempty"`

	// Encrypted content encryption key (Base64URL-encoded)
	EncryptedKey string `json:"encrypted_key"`
}

// ProtectedHeader represents the protected header shared by all recipients
type ProtectedHeader struct {
	EncryptionMethod string `json:"enc"` // Content encryption algorithm
}

// EncryptJSON encrypts data for multiple recipients in JSON serialization format.
//
// Parameters:
//   - plaintext: The data to encrypt
//   - recipients: List of recipient public keys
//   - encAlg: Content encryption algorithm ("A256GCM", "A192GCM", "A128GCM")
//   - keyAlgs: Per-recipient key encryption algorithms (same length as recipients)
//   - keyIDs: Optional per-recipient key IDs (can be nil or same length as recipients)
//
// Returns:
//   - *JSONSerialization: JWE in JSON format
//   - error: Any error during encryption
//
// Example:
//
//	recipients := []keypair.GenericPublicKey{aliceKey, bobKey, carolKey}
//	keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "ECDH-ES"}
//	keyIDs := []string{"alice-2024", "bob-2024", "carol-2024"}
//	jwe, err := jwe.EncryptJSON(plaintext, recipients, "A256GCM", keyAlgs, keyIDs)
func EncryptJSON(
	plaintext []byte,
	recipients []keypair.GenericPublicKey,
	encAlg string,
	keyAlgs []string,
	keyIDs []string,
) (*JSONSerialization, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}

	if len(keyAlgs) != len(recipients) {
		return nil, fmt.Errorf("keyAlgs length must match recipients length")
	}

	if keyIDs != nil && len(keyIDs) != len(recipients) {
		return nil, fmt.Errorf("keyIDs length must match recipients length if provided")
	}

	// Use GoPKI multi-recipient envelope encryption
	opts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmEnvelope,
		Format:    encryption.FormatCMS,
		Metadata:  make(map[string]interface{}),
	}

	encrypted, err := envelope.EncryptForMultipleRecipients(plaintext, recipients, opts)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Create protected header (shared by all recipients)
	protected := ProtectedHeader{
		EncryptionMethod: encAlg,
	}
	protectedB64, err := encoding.EncodeJSON(protected)
	if err != nil {
		return nil, fmt.Errorf("failed to encode protected header: %w", err)
	}

	// Create JSON serialization
	jwe := &JSONSerialization{
		Protected:  protectedB64,
		IV:         encoding.EncodeBytes(encrypted.IV),
		Ciphertext: encoding.EncodeBytes(encrypted.Data),
		Tag:        encoding.EncodeBytes(encrypted.Tag),
		Recipients: make([]JSONRecipient, len(recipients)),
	}

	// Create recipient entries
	for i, recipientInfo := range encrypted.Recipients {
		keyID := ""
		if keyIDs != nil {
			keyID = keyIDs[i]
		}

		jwe.Recipients[i] = JSONRecipient{
			Header: map[string]interface{}{
				"alg": keyAlgs[i],
				"kid": keyID,
			},
			EncryptedKey: encoding.EncodeBytes(recipientInfo.EncryptedKey),
		}
	}

	return jwe, nil
}

// DecryptJSON decrypts JWE JSON serialization format.
//
// The function tries all recipients until one succeeds.
//
// Type parameter:
//   - K: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - jwe: The JWE JSON serialization
//   - keyPair: The recipient's key pair
//
// Returns:
//   - []byte: The decrypted plaintext
//   - error: Any error if no recipient can decrypt
//
// Example:
//
//	plaintext, err := jwe.DecryptJSON(jweJSON, bobKeys)
func DecryptJSON[K keypair.KeyPair](jwe *JSONSerialization, keyPair K) ([]byte, error) {
	if jwe == nil {
		return nil, ErrInvalidJSON
	}

	if len(jwe.Recipients) == 0 {
		return nil, ErrNoRecipients
	}

	// Decode protected header
	var protected ProtectedHeader
	if jwe.Protected != "" {
		if err := encoding.DecodeJSON(jwe.Protected, &protected); err != nil {
			return nil, fmt.Errorf("invalid protected header: %w", err)
		}
	}

	// Decode common components
	iv, err := encoding.DecodeString(jwe.IV)
	if err != nil {
		return nil, fmt.Errorf("invalid IV encoding: %w", err)
	}

	ciphertext, err := encoding.DecodeString(jwe.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	tag, err := encoding.DecodeString(jwe.Tag)
	if err != nil {
		return nil, fmt.Errorf("invalid tag encoding: %w", err)
	}

	// Try each recipient
	var lastErr error
	for i, recipient := range jwe.Recipients {
		// Decode encrypted key
		encryptedKey, err := encoding.DecodeString(recipient.EncryptedKey)
		if err != nil {
			lastErr = fmt.Errorf("recipient %d: invalid encrypted key encoding: %w", i, err)
			continue
		}

		// Get algorithm from per-recipient header
		algValue, ok := recipient.Header["alg"]
		if !ok {
			lastErr = fmt.Errorf("recipient %d: missing alg in header", i)
			continue
		}

		algStr, ok := algValue.(string)
		if !ok {
			lastErr = fmt.Errorf("recipient %d: alg must be string", i)
			continue
		}

		keyEncAlg, err := jweAlgToGoPKIAlg(algStr)
		if err != nil {
			lastErr = fmt.Errorf("recipient %d: %w", i, err)
			continue
		}

		// Reconstruct EncryptedData
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

		// Try to decrypt with this recipient
		opts := encryption.DecryptOptions{
			ExpectedAlgorithm: encryption.AlgorithmEnvelope,
		}

		plaintext, err := envelope.Decrypt(encrypted, keyPair, opts)
		if err != nil {
			lastErr = fmt.Errorf("recipient %d: %w", i, err)
			continue
		}

		// Success!
		return plaintext, nil
	}

	// All recipients failed
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, lastErr)
	}
	return nil, ErrDecryptionFailed
}

// Marshal serializes the JWE JSON structure to JSON bytes.
func (j *JSONSerialization) Marshal() ([]byte, error) {
	return json.Marshal(j)
}

// UnmarshalJSON parses a JWE JSON serialization from JSON bytes.
func UnmarshalJSON(data []byte) (*JSONSerialization, error) {
	var jwe JSONSerialization
	if err := json.Unmarshal(data, &jwe); err != nil {
		return nil, fmt.Errorf("unmarshal JWE JSON: %w", err)
	}

	if jwe.Ciphertext == "" {
		return nil, ErrInvalidJSON
	}

	if len(jwe.Recipients) == 0 {
		return nil, ErrNoRecipients
	}

	return &jwe, nil
}
