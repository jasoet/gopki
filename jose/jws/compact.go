package jws

import (
	"encoding/json"
	"fmt"

	"github.com/jasoet/gopki/jose/jwt"
	"github.com/jasoet/gopki/keypair"
)

// SignCompact creates a JWS in compact serialization format.
// This is a thin wrapper around JWT, allowing signing of arbitrary payload
// without requiring JWT claims structure.
//
// The compact format is: BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
func SignCompact[K keypair.PrivateKey](
	payload []byte,
	key K,
	alg jwt.Algorithm,
	keyID string,
) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("payload cannot be empty")
	}

	// Try to unmarshal payload as JSON to create claims
	var payloadData map[string]interface{}
	if err := json.Unmarshal(payload, &payloadData); err != nil {
		// If not valid JSON, wrap it in a container
		payloadData = map[string]interface{}{
			"data": payload,
		}
	}

	// Create claims from payload
	claims := &jwt.Claims{
		Extra: payloadData,
	}

	// Sign using JWT
	opts := &jwt.SignOptions{
		KeyID: keyID,
	}

	return jwt.Sign(claims, key, alg, opts)
}

// VerifyCompact verifies a JWS in compact serialization format and returns the payload.
func VerifyCompact[K keypair.PublicKey](
	jws string,
	key K,
	expectedAlg jwt.Algorithm,
) ([]byte, error) {
	opts := &jwt.VerifyOptions{
		ExpectedAlgorithm: expectedAlg,
		Validation:        &jwt.ValidationOptions{
			// Disable claims validation for generic JWS
			ValidateExpiry:    false,
			ValidateNotBefore: false,
		},
	}

	verified, err := jwt.Verify(jws, key, opts)
	if err != nil {
		return nil, err
	}

	// Check if this was non-JSON data wrapped in {"data": ...}
	// This happens when SignCompact receives non-JSON payload
	if len(verified.Extra) == 1 {
		if dataVal, ok := verified.Extra["data"]; ok {
			// If the data value is a byte array (base64-decoded), return it directly
			if byteData, ok := dataVal.([]byte); ok {
				return byteData, nil
			}
			// If it's a string, return it as bytes
			if strData, ok := dataVal.(string); ok {
				return []byte(strData), nil
			}
		}
	}

	// Otherwise, marshal the entire Extra map as JSON
	payload, err := json.Marshal(verified.Extra)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	return payload, nil
}

// SignCompactWithSecret creates a JWS using HMAC (symmetric key).
func SignCompactWithSecret(
	payload []byte,
	secret []byte,
	alg jwt.Algorithm,
) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("payload cannot be empty")
	}

	// Try to unmarshal payload as JSON
	var payloadData map[string]interface{}
	if err := json.Unmarshal(payload, &payloadData); err != nil {
		payloadData = map[string]interface{}{
			"data": payload,
		}
	}

	claims := &jwt.Claims{
		Extra: payloadData,
	}

	return jwt.SignWithSecret(claims, secret, alg)
}

// VerifyCompactWithSecret verifies an HMAC-signed JWS.
func VerifyCompactWithSecret(
	jws string,
	secret []byte,
	expectedAlg jwt.Algorithm,
) ([]byte, error) {
	opts := &jwt.VerifyOptions{
		ExpectedAlgorithm: expectedAlg,
		Validation: &jwt.ValidationOptions{
			ValidateExpiry:    false,
			ValidateNotBefore: false,
		},
	}

	verified, err := jwt.VerifyWithSecret(jws, secret, opts)
	if err != nil {
		return nil, err
	}

	// Check if this was non-JSON data wrapped in {"data": ...}
	if len(verified.Extra) == 1 {
		if dataVal, ok := verified.Extra["data"]; ok {
			// If the data value is a byte array (base64-decoded), return it directly
			if byteData, ok := dataVal.([]byte); ok {
				return byteData, nil
			}
			// If it's a string, return it as bytes
			if strData, ok := dataVal.(string); ok {
				return []byte(strData), nil
			}
		}
	}

	payload, err := json.Marshal(verified.Extra)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	return payload, nil
}
