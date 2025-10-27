package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jasoet/gopki/keypair/algo"
)

// GenerateKeyOptions contains parameters for generating a key in Vault.
type GenerateKeyOptions struct {
	KeyName string // Name for the key
	KeyType string // "rsa", "ec", "ed25519"
	KeyBits int    // For RSA: 2048, 3072, 4096; For EC: 224, 256, 384, 521
}

// ImportKeyOptions contains parameters for importing a key to Vault.
type ImportKeyOptions struct {
	KeyName string // Name for the key
}

// vaultKeyResponse represents Vault's response from key endpoints.
type vaultKeyResponse struct {
	Data struct {
		KeyID   string `json:"key_id"`
		KeyName string `json:"key_name"`
		KeyType string `json:"key_type"`
		KeyBits int    `json:"key_bits,omitempty"`
	} `json:"data"`
}

// vaultKeyImportResponse represents Vault's response from key import endpoint.
type vaultKeyImportResponse struct {
	Data struct {
		KeyID   string            `json:"key_id"`
		KeyName string            `json:"key_name"`
		KeyType string            `json:"key_type"`
		Mapping map[string]string `json:"mapping,omitempty"`
	} `json:"data"`
}

// GenerateKey generates a new key in Vault.
// The key is generated and stored in Vault, never exposed outside.
//
// Example:
//
//	keyInfo, err := client.GenerateKey(ctx, &vault.GenerateKeyOptions{
//	    KeyName: "my-key",
//	    KeyType: "rsa",
//	    KeyBits: 2048,
//	})
func (c *Client) GenerateKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyInfo, error) {
	if opts == nil {
		return nil, fmt.Errorf("vault: key options are required")
	}
	if opts.KeyType == "" {
		return nil, fmt.Errorf("vault: key type is required")
	}

	// Validate key type
	switch opts.KeyType {
	case "rsa", "ec", "ed25519":
		// Valid types
	default:
		return nil, fmt.Errorf("vault: invalid key type '%s', must be 'rsa', 'ec', or 'ed25519'", opts.KeyType)
	}

	// Build request body
	reqBody := map[string]interface{}{
		"key_type": opts.KeyType,
	}

	if opts.KeyName != "" {
		reqBody["key_name"] = opts.KeyName
	}

	// Add key_bits for RSA and EC
	if opts.KeyType == "rsa" || opts.KeyType == "ec" {
		if opts.KeyBits <= 0 {
			// Set defaults
			if opts.KeyType == "rsa" {
				opts.KeyBits = 2048
			} else if opts.KeyType == "ec" {
				opts.KeyBits = 256
			}
		}
		reqBody["key_bits"] = opts.KeyBits
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/keys/generate/%s", c.config.Mount, opts.KeyType)
	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("vault: generate key: %w", err)
	}

	// Parse response
	var vaultResp vaultKeyResponse
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: generate key: %w", err)
	}

	return &KeyInfo{
		KeyID:   vaultResp.Data.KeyID,
		KeyName: vaultResp.Data.KeyName,
		KeyType: vaultResp.Data.KeyType,
		KeyBits: vaultResp.Data.KeyBits,
	}, nil
}

// ImportKey imports a GoPKI key pair into Vault.
// Only the private key is imported. The key pair must be one of:
// *algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair.
//
// Example:
//
//	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	keyInfo, err := client.ImportKey(ctx, keyPair, &vault.ImportKeyOptions{
//	    KeyName: "imported-key",
//	})
func (c *Client) ImportKey(ctx context.Context, keyPair interface{}, opts *ImportKeyOptions) (*KeyInfo, error) {
	if keyPair == nil {
		return nil, fmt.Errorf("vault: key pair is required")
	}

	var pemData string
	var keyType string
	var keyBits int

	// Extract private key PEM based on type
	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		pem, err := kp.PrivateKeyToPEM()
		if err != nil {
			return nil, fmt.Errorf("vault: convert RSA private key to PEM: %w", err)
		}
		pemData = string(pem)
		keyType = "rsa"
		keyBits = kp.PrivateKey.N.BitLen()
	case *algo.ECDSAKeyPair:
		pem, err := kp.PrivateKeyToPEM()
		if err != nil {
			return nil, fmt.Errorf("vault: convert ECDSA private key to PEM: %w", err)
		}
		pemData = string(pem)
		keyType = "ec"
		keyBits = kp.PrivateKey.Params().BitSize
	case *algo.Ed25519KeyPair:
		pem, err := kp.PrivateKeyToPEM()
		if err != nil {
			return nil, fmt.Errorf("vault: convert Ed25519 private key to PEM: %w", err)
		}
		pemData = string(pem)
		keyType = "ed25519"
		keyBits = 256 // Ed25519 is always 256 bits
	default:
		return nil, fmt.Errorf("vault: unsupported key pair type: %T", keyPair)
	}

	// Build request body
	reqBody := map[string]interface{}{
		"pem_bundle": pemData,
	}

	if opts != nil && opts.KeyName != "" {
		reqBody["key_name"] = opts.KeyName
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/keys/import", c.config.Mount)
	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("vault: import key: %w", err)
	}

	// Parse response
	var vaultResp vaultKeyImportResponse
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: import key: %w", err)
	}

	return &KeyInfo{
		KeyID:   vaultResp.Data.KeyID,
		KeyName: vaultResp.Data.KeyName,
		KeyType: keyType,
		KeyBits: keyBits,
	}, nil
}

// ListKeys lists all key IDs in the PKI mount.
//
// Example:
//
//	keys, err := client.ListKeys(ctx)
//	for _, keyID := range keys {
//	    fmt.Println(keyID)
//	}
func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/keys", c.config.Mount)
	resp, err := c.doRequest(ctx, "LIST", path, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: list keys: %w", err)
	}

	// Parse response
	var vaultResp vaultListResponse
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: list keys: %w", err)
	}

	return vaultResp.Data.Keys, nil
}

// GetKey retrieves key information by ID or name.
// Note: This does not return the private key material, only metadata.
//
// Example:
//
//	keyInfo, err := client.GetKey(ctx, "key-id-or-name")
func (c *Client) GetKey(ctx context.Context, keyRef string) (*KeyInfo, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("vault: key reference is required")
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/key/%s", c.config.Mount, keyRef)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: get key: %w", err)
	}

	// Parse response
	var vaultResp vaultKeyResponse
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: get key: %w", err)
	}

	return &KeyInfo{
		KeyID:   vaultResp.Data.KeyID,
		KeyName: vaultResp.Data.KeyName,
		KeyType: vaultResp.Data.KeyType,
		KeyBits: vaultResp.Data.KeyBits,
	}, nil
}

// DeleteKey deletes a key from Vault.
// Note: This will fail if the key is in use by any issuer.
//
// Example:
//
//	err := client.DeleteKey(ctx, "key-id")
func (c *Client) DeleteKey(ctx context.Context, keyRef string) error {
	if keyRef == "" {
		return fmt.Errorf("vault: key reference is required")
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/key/%s", c.config.Mount, keyRef)
	resp, err := c.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("vault: delete key: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("vault: delete key failed (status %d)", resp.StatusCode)
	}

	return nil
}

// UpdateKeyName updates the name of a key.
//
// Example:
//
//	err := client.UpdateKeyName(ctx, "key-id", "new-name")
func (c *Client) UpdateKeyName(ctx context.Context, keyRef string, newName string) error {
	if keyRef == "" {
		return fmt.Errorf("vault: key reference is required")
	}
	if newName == "" {
		return fmt.Errorf("vault: new key name is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"key_name": newName,
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/key/%s", c.config.Mount, keyRef)
	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return fmt.Errorf("vault: update key name: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("vault: update key name failed (status %d)", resp.StatusCode)
	}

	return nil
}

// ExportKey exports a key from Vault if the key was originally imported or if export is enabled.
// This function attempts to export the private key and convert it to a GoPKI key pair.
// Note: This will fail if the key was generated internally in Vault or if export is not allowed.
//
// The returned interface{} can be type-asserted to:
// *algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair
//
// Example:
//
//	keyPair, err := client.ExportKey(ctx, "key-id")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	rsaKeyPair := keyPair.(*algo.RSAKeyPair)
func (c *Client) ExportKey(ctx context.Context, keyRef string) (interface{}, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("vault: key reference is required")
	}

	// First get key info to determine type
	keyInfo, err := c.GetKey(ctx, keyRef)
	if err != nil {
		return nil, fmt.Errorf("vault: export key: %w", err)
	}

	// Make request to Vault export endpoint
	// Note: This endpoint may not exist or may be disabled by policy
	path := fmt.Sprintf("/v1/%s/key/%s/export", c.config.Mount, keyRef)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: export key: %w (key may not be exportable)", err)
	}

	// Parse response
	var vaultResp struct {
		Data struct {
			PrivateKey string `json:"private_key"`
			KeyType    string `json:"key_type"`
		} `json:"data"`
	}
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: export key: %w", err)
	}

	// Parse private key PEM
	block, _ := pem.Decode([]byte(vaultResp.Data.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("vault: export key: failed to decode PEM")
	}

	// Convert to GoPKI key pair based on type
	switch keyInfo.KeyType {
	case "rsa":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("vault: export key: parse RSA private key: %w", err)
			}
			var ok bool
			privateKey, ok = pkcs8Key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("vault: export key: expected RSA key, got %T", pkcs8Key)
			}
		}

		return &algo.RSAKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil

	case "ec":
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("vault: export key: parse ECDSA private key: %w", err)
			}
			var ok bool
			privateKey, ok = pkcs8Key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("vault: export key: expected ECDSA key, got %T", pkcs8Key)
			}
		}

		return &algo.ECDSAKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil

	case "ed25519":
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("vault: export key: parse Ed25519 private key: %w", err)
		}

		privateKey, ok := pkcs8Key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("vault: export key: expected Ed25519 key, got %T", pkcs8Key)
		}

		publicKey := privateKey.Public().(ed25519.PublicKey)

		return &algo.Ed25519KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}, nil

	default:
		return nil, fmt.Errorf("vault: export key: unsupported key type '%s'", keyInfo.KeyType)
	}
}
