package bao

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// GenerateKeyOptions contains parameters for generating a key in OpenBao.
type GenerateKeyOptions struct {
	KeyName  string // Name for the key
	KeyType  string // "rsa", "ec", "ed25519"
	KeyBits  int    // For RSA: 2048, 3072, 4096; For EC: 224, 256, 384, 521
	Exported bool   // If true, private key is returned; if false, key stays in OpenBao
}

// ImportKeyOptions contains parameters for importing a key to OpenBao.
type ImportKeyOptions struct {
	KeyName string // Name for the key
}

// GenerateKey generates a new key in OpenBao.
// The key is generated and stored in OpenBao, never exposed outside.
//
// Example:
//
//	keyInfo, err := client.GenerateKey(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-key",
//	    KeyType: "rsa",
//	    KeyBits: 2048,
//	})
func (c *Client) GenerateKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyInfo, error) {
	if opts == nil {
		return nil, fmt.Errorf("bao: key options are required")
	}
	if opts.KeyType == "" {
		return nil, fmt.Errorf("bao: key type is required")
	}

	// Validate key type
	switch opts.KeyType {
	case "rsa", "ec", "ed25519":
		// Valid types
	default:
		return nil, fmt.Errorf("bao: invalid key type '%s', must be 'rsa', 'ec', or 'ed25519'", opts.KeyType)
	}

	// Build request body
	reqBody := map[string]any{
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

	// Determine export type
	exportType := "internal" // Default: key stays in OpenBao
	if opts.Exported {
		exportType = "exported" // Key is returned in response
	}

	// Use SDK to generate key
	// Path: /pki/keys/generate/{internal|exported}
	path := fmt.Sprintf("%s/keys/generate/%s", c.config.Mount, exportType)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: generate key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: generate key: empty response")
	}

	// Extract key data
	keyID, _ := secret.Data["key_id"].(string)
	keyName, _ := secret.Data["key_name"].(string)
	keyType, _ := secret.Data["key_type"].(string)

	// KeyBits might be int or json.Number, handle both
	var keyBits int
	switch v := secret.Data["key_bits"].(type) {
	case int:
		keyBits = v
	case float64:
		keyBits = int(v)
	case int64:
		keyBits = int(v)
	}

	return &KeyInfo{
		KeyID:   keyID,
		KeyName: keyName,
		KeyType: keyType,
		KeyBits: keyBits,
	}, nil
}

// ImportKey imports a GoPKI key pair into OpenBao.
// The key pair must be one of: *algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair.
// This function is type-safe through compile-time validation of the keypair types.
//
// Example:
//
//	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	keyInfo, err := client.ImportKey(ctx, rsaKeys, &bao.ImportKeyOptions{
//	    KeyName: "imported-rsa-key",
//	})
//
//	ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	keyInfo, err := client.ImportKey(ctx, ecKeys, &bao.ImportKeyOptions{
//	    KeyName: "imported-ec-key",
//	})
func (c *Client) ImportKey(ctx context.Context, kp keypair.GenericKeyPair, opts *ImportKeyOptions) (*KeyInfo, error) {
	if kp == nil {
		return nil, fmt.Errorf("bao: key pair is required")
	}

	var pemData string
	var keyType string
	var keyBits int

	// Extract private key PEM based on type using type switch
	switch keyPair := kp.(type) {
	case *algo.RSAKeyPair:
		pemBytes, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			return nil, fmt.Errorf("bao: convert RSA private key to PEM: %w", err)
		}
		pemData = string(pemBytes)
		keyType = "rsa"
		keyBits = keyPair.PrivateKey.N.BitLen()

	case *algo.ECDSAKeyPair:
		pemBytes, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			return nil, fmt.Errorf("bao: convert ECDSA private key to PEM: %w", err)
		}
		pemData = string(pemBytes)
		keyType = "ec"
		keyBits = keyPair.PrivateKey.Params().BitSize

	case *algo.Ed25519KeyPair:
		pemBytes, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			return nil, fmt.Errorf("bao: convert Ed25519 private key to PEM: %w", err)
		}
		pemData = string(pemBytes)
		keyType = "ed25519"
		keyBits = 256 // Ed25519 is always 256 bits

	default:
		return nil, fmt.Errorf("bao: unsupported key pair type: %T", keyPair)
	}

	// Build request body
	reqBody := map[string]any{
		"pem_bundle": pemData,
	}

	if opts != nil && opts.KeyName != "" {
		reqBody["key_name"] = opts.KeyName
	}

	// Use SDK to import key
	path := fmt.Sprintf("%s/keys/import", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: import key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: import key: empty response")
	}

	// Extract key data
	keyID, _ := secret.Data["key_id"].(string)
	keyName, _ := secret.Data["key_name"].(string)

	return &KeyInfo{
		KeyID:   keyID,
		KeyName: keyName,
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
	// Use SDK to list keys
	path := fmt.Sprintf("%s/keys", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: list keys: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// Extract keys from response
	keys, ok := secret.Data["keys"].([]any)
	if !ok {
		return []string{}, nil
	}

	// Convert to string slice
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	return result, nil
}

// GetKey retrieves key information by ID or name.
// Note: This does not return the private key material, only metadata.
//
// Example:
//
//	keyInfo, err := client.GetKey(ctx, "key-id-or-name")
func (c *Client) GetKey(ctx context.Context, keyRef string) (*KeyInfo, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	// Use SDK to get key
	path := fmt.Sprintf("%s/key/%s", c.config.Mount, keyRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: get key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: get key: not found")
	}

	// Extract key data
	keyID, _ := secret.Data["key_id"].(string)
	keyName, _ := secret.Data["key_name"].(string)
	keyType, _ := secret.Data["key_type"].(string)

	// KeyBits might be int or json.Number, handle both
	var keyBits int
	switch v := secret.Data["key_bits"].(type) {
	case int:
		keyBits = v
	case float64:
		keyBits = int(v)
	case int64:
		keyBits = int(v)
	}

	return &KeyInfo{
		KeyID:   keyID,
		KeyName: keyName,
		KeyType: keyType,
		KeyBits: keyBits,
	}, nil
}

// DeleteKey deletes a key from OpenBao.
// Note: This will fail if the key is in use by any issuer.
//
// Example:
//
//	err := client.DeleteKey(ctx, "key-id")
func (c *Client) DeleteKey(ctx context.Context, keyRef string) error {
	if keyRef == "" {
		return fmt.Errorf("bao: key reference is required")
	}

	// Use SDK to delete key
	path := fmt.Sprintf("%s/key/%s", c.config.Mount, keyRef)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("bao: delete key: %w", err)
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
		return fmt.Errorf("bao: key reference is required")
	}
	if newName == "" {
		return fmt.Errorf("bao: new key name is required")
	}

	// Build request body
	reqBody := map[string]any{
		"key_name": newName,
	}

	// Use SDK to update key name
	path := fmt.Sprintf("%s/key/%s", c.config.Mount, keyRef)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: update key name: %w", err)
	}

	return nil
}

// ExportRSAKey exports an RSA key from OpenBao.
// This function attempts to export the private key and convert it to an RSA key pair.
// Note: This will fail if the key was generated internally in OpenBao without export enabled.
//
// Example:
//
//	rsaKeyPair, err := client.ExportRSAKey(ctx, "rsa-key-id")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use rsaKeyPair.PrivateKey, rsaKeyPair.PublicKey
func (c *Client) ExportRSAKey(ctx context.Context, keyRef string) (*algo.RSAKeyPair, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	// Use SDK to export key
	path := fmt.Sprintf("%s/key/%s/export", c.config.Mount, keyRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: export RSA key: %w (key may not be exportable)", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: export RSA key: empty response")
	}

	// Extract private key data
	privateKeyPEM, ok := secret.Data["private_key"].(string)
	if !ok || privateKeyPEM == "" {
		return nil, fmt.Errorf("bao: export RSA key: no private key in response")
	}

	// Parse private key PEM
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("bao: export RSA key: failed to decode PEM")
	}

	// Try PKCS#1 first
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS#8 format
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bao: export RSA key: parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("bao: export RSA key: expected RSA key, got %T", pkcs8Key)
		}
	}

	return &algo.RSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// ExportECDSAKey exports an ECDSA key from OpenBao.
// This function attempts to export the private key and convert it to an ECDSA key pair.
// Note: This will fail if the key was generated internally in OpenBao without export enabled.
//
// Example:
//
//	ecKeyPair, err := client.ExportECDSAKey(ctx, "ec-key-id")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use ecKeyPair.PrivateKey, ecKeyPair.PublicKey
func (c *Client) ExportECDSAKey(ctx context.Context, keyRef string) (*algo.ECDSAKeyPair, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	// Use SDK to export key
	path := fmt.Sprintf("%s/key/%s/export", c.config.Mount, keyRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: export ECDSA key: %w (key may not be exportable)", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: export ECDSA key: empty response")
	}

	// Extract private key data
	privateKeyPEM, ok := secret.Data["private_key"].(string)
	if !ok || privateKeyPEM == "" {
		return nil, fmt.Errorf("bao: export ECDSA key: no private key in response")
	}

	// Parse private key PEM
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("bao: export ECDSA key: failed to decode PEM")
	}

	// Try EC private key format first
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS#8 format
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bao: export ECDSA key: parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("bao: export ECDSA key: expected ECDSA key, got %T", pkcs8Key)
		}
	}

	return &algo.ECDSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// ExportEd25519Key exports an Ed25519 key from OpenBao.
// This function attempts to export the private key and convert it to an Ed25519 key pair.
// Note: This will fail if the key was generated internally in OpenBao without export enabled.
//
// Example:
//
//	edKeyPair, err := client.ExportEd25519Key(ctx, "ed25519-key-id")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use edKeyPair.PrivateKey, edKeyPair.PublicKey
func (c *Client) ExportEd25519Key(ctx context.Context, keyRef string) (*algo.Ed25519KeyPair, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	// Use SDK to export key
	path := fmt.Sprintf("%s/key/%s/export", c.config.Mount, keyRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: export Ed25519 key: %w (key may not be exportable)", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: export Ed25519 key: empty response")
	}

	// Extract private key data
	privateKeyPEM, ok := secret.Data["private_key"].(string)
	if !ok || privateKeyPEM == "" {
		return nil, fmt.Errorf("bao: export Ed25519 key: no private key in response")
	}

	// Parse private key PEM
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("bao: export Ed25519 key: failed to decode PEM")
	}

	// Ed25519 keys are always in PKCS#8 format
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bao: export Ed25519 key: parse private key: %w", err)
	}

	privateKey, ok := pkcs8Key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bao: export Ed25519 key: expected Ed25519 key, got %T", pkcs8Key)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &algo.Ed25519KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}
