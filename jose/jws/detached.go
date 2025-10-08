package jws

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jasoet/gopki/jose/jwt"
	"github.com/jasoet/gopki/keypair"
)

// SignDetached creates a JWS with detached content in compact serialization.
// The payload is not included in the JWS, only the header and signature.
// This is useful for large payloads where the payload is transmitted separately.
//
// Format: BASE64URL(header)..BASE64URL(signature)
// Note the empty payload section (double dots)
func SignDetached[K keypair.PrivateKey](
	content []byte,
	key K,
	alg jwt.Algorithm,
	keyID string,
) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("content cannot be empty")
	}

	// Sign normally to get the full JWS
	fullJWS, err := SignCompact(content, key, alg, keyID)
	if err != nil {
		return "", err
	}

	// Split into parts
	parts := strings.Split(fullJWS, ".")
	if len(parts) != 3 {
		return "", ErrInvalidFormat
	}

	// Remove payload (middle part), keep header and signature
	// Result: header..signature
	return parts[0] + ".." + parts[2], nil
}

// VerifyDetached verifies a JWS with detached content.
// The content must be provided externally and is used to reconstruct
// the full JWS for verification.
func VerifyDetached[K keypair.PublicKey](
	detachedJWS string,
	content []byte,
	key K,
	expectedAlg jwt.Algorithm,
) error {
	if len(content) == 0 {
		return fmt.Errorf("content cannot be empty")
	}

	// Split the detached JWS
	parts := strings.Split(detachedJWS, ".")
	if len(parts) != 3 {
		return ErrInvalidDetachedFormat
	}

	// Verify the middle part is empty
	if parts[1] != "" {
		return ErrInvalidDetachedFormat
	}

	// We need to recreate the payload exactly as SignDetached did.
	// SignDetached uses SignCompact, which wraps non-JSON content in {"data": ...}
	// So we need to do the same transformation here.

	// Try to unmarshal content as JSON
	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil {
		// If not valid JSON, wrap it in a container (same as SignCompact does)
		payloadData = map[string]interface{}{
			"data": content,
		}
	}

	// Marshal to JSON (same as SignCompact does)
	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// Base64URL encode the JSON payload
	contentB64 := base64URLEncode(payloadJSON)

	// Reconstruct full JWS: header.payload.signature
	fullJWS := parts[0] + "." + contentB64 + "." + parts[2]

	// Verify using normal compact verification
	_, err = VerifyCompact(fullJWS, key, expectedAlg)
	return err
}

// SignDetachedWithSecret creates a detached JWS using HMAC.
func SignDetachedWithSecret(
	content []byte,
	secret []byte,
	alg jwt.Algorithm,
) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("content cannot be empty")
	}

	// Sign normally
	fullJWS, err := SignCompactWithSecret(content, secret, alg)
	if err != nil {
		return "", err
	}

	// Split and remove payload
	parts := strings.Split(fullJWS, ".")
	if len(parts) != 3 {
		return "", ErrInvalidFormat
	}

	return parts[0] + ".." + parts[2], nil
}

// VerifyDetachedWithSecret verifies a detached HMAC-signed JWS.
func VerifyDetachedWithSecret(
	detachedJWS string,
	content []byte,
	secret []byte,
	expectedAlg jwt.Algorithm,
) error {
	if len(content) == 0 {
		return fmt.Errorf("content cannot be empty")
	}

	// Split the detached JWS
	parts := strings.Split(detachedJWS, ".")
	if len(parts) != 3 || parts[1] != "" {
		return ErrInvalidDetachedFormat
	}

	// Recreate the payload exactly as SignDetachedWithSecret did
	// Try to unmarshal content as JSON
	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil {
		// If not valid JSON, wrap it in a container
		payloadData = map[string]interface{}{
			"data": content,
		}
	}

	// Marshal to JSON
	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// Base64URL encode the JSON payload
	contentB64 := base64URLEncode(payloadJSON)

	// Reconstruct full JWS
	fullJWS := parts[0] + "." + contentB64 + "." + parts[2]

	// Verify
	_, err = VerifyCompactWithSecret(fullJWS, secret, expectedAlg)
	return err
}
