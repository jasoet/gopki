package jws

import (
	"encoding/json"
	"fmt"
)

// JSONSerialization represents JWS in JSON serialization format.
// This format supports multiple signatures on the same payload.
//
// Example:
//
//	{
//	  "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODB9",
//	  "signatures": [
//	    {
//	      "protected": "eyJhbGciOiJSUzI1NiJ9",
//	      "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB..."
//	    }
//	  ]
//	}
type JSONSerialization struct {
	// Payload is the Base64URL-encoded payload
	Payload string `json:"payload"`

	// Signatures contains one or more signatures
	Signatures []JSONSignature `json:"signatures"`
}

// JSONSignature represents a single signature in JSON serialization.
type JSONSignature struct {
	// Protected is the Base64URL-encoded protected header
	Protected string `json:"protected,omitempty"`

	// Header contains unprotected header parameters
	Header map[string]interface{} `json:"header,omitempty"`

	// Signature is the Base64URL-encoded signature value
	Signature string `json:"signature"`
}

// SignJSON creates a JWS in JSON serialization format with multiple signatures.
// This allows the same payload to be signed by multiple keys.
func SignJSON(payload []byte, signers []*Signer) (*JSONSerialization, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("payload cannot be empty")
	}

	if len(signers) == 0 {
		return nil, ErrNoSignatures
	}

	// Base64URL encode the payload
	payloadB64 := base64URLEncode(payload)

	jws := &JSONSerialization{
		Payload:    payloadB64,
		Signatures: make([]JSONSignature, 0, len(signers)),
	}

	// Create a signature for each signer
	for i, signer := range signers {
		if signer == nil {
			return nil, fmt.Errorf("signer %d is nil", i)
		}

		// Create protected header
		header := map[string]interface{}{
			"alg": string(signer.Algorithm),
		}

		if signer.KeyID != "" {
			header["kid"] = signer.KeyID
		}

		// Encode protected header
		headerBytes, err := json.Marshal(header)
		if err != nil {
			return nil, fmt.Errorf("marshal header for signer %d: %w", i, err)
		}

		protectedB64 := base64URLEncode(headerBytes)

		// Create signing input: BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)
		signingInput := protectedB64 + "." + payloadB64

		// Sign the input
		signature, err := signer.Sign([]byte(signingInput))
		if err != nil {
			return nil, fmt.Errorf("sign with signer %d (%s): %w", i, signer.KeyID, err)
		}

		// Add signature to the list
		jws.Signatures = append(jws.Signatures, JSONSignature{
			Protected:  protectedB64,
			Header:     signer.UnprotectedHeader,
			Signature:  base64URLEncode(signature),
		})
	}

	return jws, nil
}

// VerifyJSON verifies a JWS in JSON serialization format.
// At least one signature must be valid for verification to succeed.
// The function returns the payload if any signature is valid.
func VerifyJSON(jws *JSONSerialization, verifiers []*Verifier) ([]byte, error) {
	if jws == nil {
		return nil, ErrInvalidJSON
	}

	if len(jws.Signatures) == 0 {
		return nil, ErrNoSignatures
	}

	if len(verifiers) == 0 {
		return nil, fmt.Errorf("no verifiers provided")
	}

	// Decode payload
	payload, err := base64URLDecode(jws.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	// Try to verify each signature with each verifier
	var verified bool
	for sigIdx, sig := range jws.Signatures {
		// Decode the signature
		sigBytes, err := base64URLDecode(sig.Signature)
		if err != nil {
			continue // Skip invalid signature
		}

		// Parse protected header to get algorithm
		var protectedHeader struct {
			Algorithm string `json:"alg"`
			KeyID     string `json:"kid"`
		}

		if sig.Protected != "" {
			headerBytes, err := base64URLDecode(sig.Protected)
			if err != nil {
				continue
			}

			if err := json.Unmarshal(headerBytes, &protectedHeader); err != nil {
				continue
			}
		}

		// Create signing input
		signingInput := sig.Protected + "." + jws.Payload

		// Try each verifier
		for _, verifier := range verifiers {
			if verifier == nil {
				continue
			}

			// Check if key ID matches (if specified)
			if verifier.KeyID != "" && protectedHeader.KeyID != "" {
				if verifier.KeyID != protectedHeader.KeyID {
					continue
				}
			}

			// Check if algorithm matches
			if protectedHeader.Algorithm != "" {
				if string(verifier.Algorithm) != protectedHeader.Algorithm {
					continue
				}
			}

			// Verify signature
			if verifier.Verify([]byte(signingInput), sigBytes) {
				verified = true
				break
			}
		}

		if verified {
			break
		}

		// Continue to next signature if this one didn't verify
		_ = sigIdx // Used for potential error reporting
	}

	if !verified {
		return nil, ErrNoValidSignature
	}

	return payload, nil
}

// Marshal serializes the JWS JSON structure to JSON bytes.
func (j *JSONSerialization) Marshal() ([]byte, error) {
	return json.Marshal(j)
}

// UnmarshalJSON parses a JWS JSON serialization from JSON bytes.
func UnmarshalJSON(data []byte) (*JSONSerialization, error) {
	var jws JSONSerialization
	if err := json.Unmarshal(data, &jws); err != nil {
		return nil, fmt.Errorf("unmarshal JWS JSON: %w", err)
	}

	if jws.Payload == "" {
		return nil, ErrInvalidJSON
	}

	if len(jws.Signatures) == 0 {
		return nil, ErrNoSignatures
	}

	return &jws, nil
}

