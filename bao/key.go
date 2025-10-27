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

// ============================================================================
// Options
// ============================================================================

// GenerateKeyOptions contains parameters for generating a key in OpenBao.
type GenerateKeyOptions struct {
	KeyName  string // Name for the key
	KeyType  string // "rsa", "ec", "ed25519" (set automatically by typed functions)
	KeyBits  int    // For RSA: 2048, 3072, 4096; For EC: 224, 256, 384, 521
	Exported bool   // If true, private key is returned; if false, key stays in OpenBao
}

// ImportKeyOptions contains parameters for importing a key to OpenBao.
type ImportKeyOptions struct {
	KeyName string // Name for the key
}

// ============================================================================
// KeyClient[K] - Type-safe key operations
// ============================================================================

// KeyClient provides type-safe key operations for OpenBao PKI.
// It uses generics to ensure compile-time type safety for key material operations.
//
// Type parameter:
//   - K: KeyPair type constraint (keypair.KeyPair)
//
// Supported types:
//   - *algo.RSAKeyPair
//   - *algo.ECDSAKeyPair
//   - *algo.Ed25519KeyPair
type KeyClient[K keypair.KeyPair] struct {
	client  *Client
	keyInfo *KeyInfo
}

// KeyInfo returns the key metadata.
func (kc *KeyClient[K]) KeyInfo() *KeyInfo {
	return kc.keyInfo
}

// Export exports the key pair from OpenBao with full type safety.
// Returns the exact key pair type K.
//
// Example:
//
//	rsaKeys, _ := bao.GetRSAKey(ctx, client, "key-id")
//	keyPair, err := rsaKeys.Export(ctx)  // Returns *algo.RSAKeyPair
func (kc *KeyClient[K]) Export(ctx context.Context) (K, error) {
	var zero K

	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return zero, fmt.Errorf("bao: key info not available")
	}

	// Use SDK to export key
	path := fmt.Sprintf("%s/key/%s/export", kc.client.config.Mount, kc.keyInfo.KeyID)
	secret, err := kc.client.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return zero, fmt.Errorf("bao: export key: %w (key may not be exportable)", err)
	}
	if secret == nil || secret.Data == nil {
		return zero, fmt.Errorf("bao: export key: empty response")
	}

	// Extract private key data
	privateKeyPEM, ok := secret.Data["private_key"].(string)
	if !ok || privateKeyPEM == "" {
		return zero, fmt.Errorf("bao: export key: no private key in response")
	}

	// Parse private key PEM
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return zero, fmt.Errorf("bao: export key: failed to decode PEM")
	}

	// Parse based on key type from keyInfo
	switch kc.keyInfo.KeyType {
	case "rsa":
		// Try PKCS#1 first
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS#8 format
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return zero, fmt.Errorf("bao: export RSA key: parse private key: %w", err)
			}
			var ok bool
			privateKey, ok = pkcs8Key.(*rsa.PrivateKey)
			if !ok {
				return zero, fmt.Errorf("bao: export RSA key: expected RSA key, got %T", pkcs8Key)
			}
		}

		keyPair := &algo.RSAKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}
		return any(keyPair).(K), nil

	case "ec":
		// Try EC private key format first
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS#8 format
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return zero, fmt.Errorf("bao: export ECDSA key: parse private key: %w", err)
			}
			var ok bool
			privateKey, ok = pkcs8Key.(*ecdsa.PrivateKey)
			if !ok {
				return zero, fmt.Errorf("bao: export ECDSA key: expected ECDSA key, got %T", pkcs8Key)
			}
		}

		keyPair := &algo.ECDSAKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}
		return any(keyPair).(K), nil

	case "ed25519":
		// Ed25519 keys are always in PKCS#8 format
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return zero, fmt.Errorf("bao: export Ed25519 key: parse private key: %w", err)
		}

		privateKey, ok := pkcs8Key.(ed25519.PrivateKey)
		if !ok {
			return zero, fmt.Errorf("bao: export Ed25519 key: expected Ed25519 key, got %T", pkcs8Key)
		}

		publicKey := privateKey.Public().(ed25519.PublicKey)

		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
		return any(keyPair).(K), nil

	default:
		return zero, fmt.Errorf("bao: export key: unsupported key type '%s'", kc.keyInfo.KeyType)
	}
}

// Delete deletes this key from OpenBao.
//
// Example:
//
//	rsaKeys, _ := bao.GetRSAKey(ctx, client, "key-id")
//	err := rsaKeys.Delete(ctx)
func (kc *KeyClient[K]) Delete(ctx context.Context) error {
	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return fmt.Errorf("bao: key info not available")
	}

	path := fmt.Sprintf("%s/key/%s", kc.client.config.Mount, kc.keyInfo.KeyID)
	_, err := kc.client.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("bao: delete key: %w", err)
	}

	return nil
}

// UpdateName updates this key's name.
//
// Example:
//
//	rsaKeys, _ := bao.GetRSAKey(ctx, client, "key-id")
//	err := rsaKeys.UpdateName(ctx, "new-name")
func (kc *KeyClient[K]) UpdateName(ctx context.Context, newName string) error {
	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return fmt.Errorf("bao: key info not available")
	}
	if newName == "" {
		return fmt.Errorf("bao: new key name is required")
	}

	reqBody := map[string]interface{}{
		"key_name": newName,
	}

	path := fmt.Sprintf("%s/key/%s", kc.client.config.Mount, kc.keyInfo.KeyID)
	_, err := kc.client.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: update key name: %w", err)
	}

	// Update cached keyInfo
	kc.keyInfo.KeyName = newName

	return nil
}

// ============================================================================
// Client Methods - Type-agnostic operations
// ============================================================================

// ListKeys lists all key IDs in the PKI mount (all types).
//
// Example:
//
//	keys, err := client.ListKeys(ctx)
//	for _, keyID := range keys {
//	    fmt.Println(keyID)
//	}
func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/keys", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: list keys: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	return result, nil
}

// GetKey retrieves key metadata by ID or name (returns metadata only, not key material).
//
// Example:
//
//	keyInfo, err := client.GetKey(ctx, "key-id-or-name")
//	fmt.Println(keyInfo.KeyType)  // "rsa", "ec", or "ed25519"
func (c *Client) GetKey(ctx context.Context, keyRef string) (*KeyInfo, error) {
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	path := fmt.Sprintf("%s/key/%s", c.config.Mount, keyRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: get key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: get key: not found")
	}

	keyID, _ := secret.Data["key_id"].(string)
	keyName, _ := secret.Data["key_name"].(string)
	keyType, _ := secret.Data["key_type"].(string)

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

// DeleteKey deletes a key from OpenBao by ID or name.
//
// Example:
//
//	err := client.DeleteKey(ctx, "key-id")
func (c *Client) DeleteKey(ctx context.Context, keyRef string) error {
	if keyRef == "" {
		return fmt.Errorf("bao: key reference is required")
	}

	path := fmt.Sprintf("%s/key/%s", c.config.Mount, keyRef)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("bao: delete key: %w", err)
	}

	return nil
}

// UpdateKeyName updates the name of a key by ID or name.
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

	reqBody := map[string]interface{}{
		"key_name": newName,
	}

	path := fmt.Sprintf("%s/key/%s", c.config.Mount, keyRef)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: update key name: %w", err)
	}

	return nil
}

// ============================================================================
// Generate Key - Entry Points
// ============================================================================

// GenerateRSAKey generates an RSA key in OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	rsaKeys, err := bao.GenerateRSAKey(ctx, client, &bao.GenerateKeyOptions{
//	    KeyName: "my-rsa-key",
//	    KeyBits: 2048,
//	})
func GenerateRSAKey(ctx context.Context, client *Client, opts *GenerateKeyOptions) (*KeyClient[*algo.RSAKeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "rsa"
	if opts.KeyBits == 0 {
		opts.KeyBits = 2048
	}
	return generateKeyTyped[*algo.RSAKeyPair](ctx, client, opts)
}

// GenerateECDSAKey generates an ECDSA key in OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	ecKeys, err := bao.GenerateECDSAKey(ctx, client, &bao.GenerateKeyOptions{
//	    KeyName: "my-ec-key",
//	    KeyBits: 256,
//	})
func GenerateECDSAKey(ctx context.Context, client *Client, opts *GenerateKeyOptions) (*KeyClient[*algo.ECDSAKeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "ec"
	if opts.KeyBits == 0 {
		opts.KeyBits = 256
	}
	return generateKeyTyped[*algo.ECDSAKeyPair](ctx, client, opts)
}

// GenerateEd25519Key generates an Ed25519 key in OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	edKeys, err := bao.GenerateEd25519Key(ctx, client, &bao.GenerateKeyOptions{
//	    KeyName: "my-ed25519-key",
//	})
func GenerateEd25519Key(ctx context.Context, client *Client, opts *GenerateKeyOptions) (*KeyClient[*algo.Ed25519KeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "ed25519"
	return generateKeyTyped[*algo.Ed25519KeyPair](ctx, client, opts)
}

// generateKeyTyped is the internal generic implementation for key generation.
func generateKeyTyped[K keypair.KeyPair](ctx context.Context, client *Client, opts *GenerateKeyOptions) (*KeyClient[K], error) {
	if opts == nil {
		return nil, fmt.Errorf("bao: key options are required")
	}
	if opts.KeyType == "" {
		return nil, fmt.Errorf("bao: key type is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"key_type": opts.KeyType,
	}

	if opts.KeyName != "" {
		reqBody["key_name"] = opts.KeyName
	}

	if opts.KeyType == "rsa" || opts.KeyType == "ec" {
		reqBody["key_bits"] = opts.KeyBits
	}

	// Determine export type
	exportType := "internal"
	if opts.Exported {
		exportType = "exported"
	}

	// Use SDK to generate key
	path := fmt.Sprintf("%s/keys/generate/%s", client.config.Mount, exportType)
	secret, err := client.client.Logical().WriteWithContext(ctx, path, reqBody)
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

	var keyBits int
	switch v := secret.Data["key_bits"].(type) {
	case int:
		keyBits = v
	case float64:
		keyBits = int(v)
	case int64:
		keyBits = int(v)
	}

	return &KeyClient[K]{
		client: client,
		keyInfo: &KeyInfo{
			KeyID:   keyID,
			KeyName: keyName,
			KeyType: keyType,
			KeyBits: keyBits,
		},
	}, nil
}

// ============================================================================
// Import Key - Entry Points
// ============================================================================

// ImportRSAKey imports an RSA key pair into OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	rsaKeys, err := bao.ImportRSAKey(ctx, client, rsaKeyPair, &bao.ImportKeyOptions{
//	    KeyName: "imported-rsa-key",
//	})
func ImportRSAKey(ctx context.Context, client *Client, kp *algo.RSAKeyPair, opts *ImportKeyOptions) (*KeyClient[*algo.RSAKeyPair], error) {
	return importKeyTyped[*algo.RSAKeyPair](ctx, client, kp, opts)
}

// ImportECDSAKey imports an ECDSA key pair into OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	ecKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	ecKeys, err := bao.ImportECDSAKey(ctx, client, ecKeyPair, &bao.ImportKeyOptions{
//	    KeyName: "imported-ec-key",
//	})
func ImportECDSAKey(ctx context.Context, client *Client, kp *algo.ECDSAKeyPair, opts *ImportKeyOptions) (*KeyClient[*algo.ECDSAKeyPair], error) {
	return importKeyTyped[*algo.ECDSAKeyPair](ctx, client, kp, opts)
}

// ImportEd25519Key imports an Ed25519 key pair into OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	edKeyPair, _ := algo.GenerateEd25519KeyPair()
//	edKeys, err := bao.ImportEd25519Key(ctx, client, edKeyPair, &bao.ImportKeyOptions{
//	    KeyName: "imported-ed25519-key",
//	})
func ImportEd25519Key(ctx context.Context, client *Client, kp *algo.Ed25519KeyPair, opts *ImportKeyOptions) (*KeyClient[*algo.Ed25519KeyPair], error) {
	return importKeyTyped[*algo.Ed25519KeyPair](ctx, client, kp, opts)
}

// importKeyTyped is the internal generic implementation for key import.
func importKeyTyped[K keypair.KeyPair](ctx context.Context, client *Client, kp K, opts *ImportKeyOptions) (*KeyClient[K], error) {
	if any(kp) == nil {
		return nil, fmt.Errorf("bao: key pair is required")
	}

	var pemData string
	var keyType string
	var keyBits int

	// Extract private key PEM based on type using type switch
	switch keyPair := any(kp).(type) {
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
		keyBits = 256

	default:
		return nil, fmt.Errorf("bao: unsupported key pair type: %T", keyPair)
	}

	// Build request body
	reqBody := map[string]interface{}{
		"pem_bundle": pemData,
	}

	if opts != nil && opts.KeyName != "" {
		reqBody["key_name"] = opts.KeyName
	}

	// Use SDK to import key
	path := fmt.Sprintf("%s/keys/import", client.config.Mount)
	secret, err := client.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: import key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: import key: empty response")
	}

	// Extract key data
	keyID, _ := secret.Data["key_id"].(string)
	keyName, _ := secret.Data["key_name"].(string)

	return &KeyClient[K]{
		client: client,
		keyInfo: &KeyInfo{
			KeyID:   keyID,
			KeyName: keyName,
			KeyType: keyType,
			KeyBits: keyBits,
		},
	}, nil
}

// ============================================================================
// Get Key - Entry Points
// ============================================================================

// GetRSAKey retrieves an RSA key reference from OpenBao and returns a type-safe KeyClient.
// Use Export() to retrieve the actual key material.
//
// Example:
//
//	rsaKeys, err := bao.GetRSAKey(ctx, client, "rsa-key-id")
//	keyPair, err := rsaKeys.Export(ctx)
func GetRSAKey(ctx context.Context, client *Client, keyRef string) (*KeyClient[*algo.RSAKeyPair], error) {
	return getKeyTyped[*algo.RSAKeyPair](ctx, client, keyRef, "rsa")
}

// GetECDSAKey retrieves an ECDSA key reference from OpenBao and returns a type-safe KeyClient.
// Use Export() to retrieve the actual key material.
//
// Example:
//
//	ecKeys, err := bao.GetECDSAKey(ctx, client, "ec-key-id")
//	keyPair, err := ecKeys.Export(ctx)
func GetECDSAKey(ctx context.Context, client *Client, keyRef string) (*KeyClient[*algo.ECDSAKeyPair], error) {
	return getKeyTyped[*algo.ECDSAKeyPair](ctx, client, keyRef, "ec")
}

// GetEd25519Key retrieves an Ed25519 key reference from OpenBao and returns a type-safe KeyClient.
// Use Export() to retrieve the actual key material.
//
// Example:
//
//	edKeys, err := bao.GetEd25519Key(ctx, client, "ed25519-key-id")
//	keyPair, err := edKeys.Export(ctx)
func GetEd25519Key(ctx context.Context, client *Client, keyRef string) (*KeyClient[*algo.Ed25519KeyPair], error) {
	return getKeyTyped[*algo.Ed25519KeyPair](ctx, client, keyRef, "ed25519")
}

// getKeyTyped is the internal generic implementation for key retrieval.
func getKeyTyped[K keypair.KeyPair](ctx context.Context, client *Client, keyRef string, expectedType string) (*KeyClient[K], error) {
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	// Get key metadata
	keyInfo, err := client.GetKey(ctx, keyRef)
	if err != nil {
		return nil, err
	}

	// Validate key type matches expected type
	if keyInfo.KeyType != expectedType {
		return nil, fmt.Errorf("bao: key type mismatch: expected %s, got %s", expectedType, keyInfo.KeyType)
	}

	return &KeyClient[K]{
		client:  client,
		keyInfo: keyInfo,
	}, nil
}
