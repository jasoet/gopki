package bao

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// Options
// ============================================================================

// GenerateKeyOptions contains parameters for generating a key in OpenBao.
type GenerateKeyOptions struct {
	KeyName string // Name for the key
	KeyType string // "rsa", "ec", "ed25519" (set automatically by typed functions)
	KeyBits int    // For RSA: 2048, 3072, 4096; For EC: 224, 256, 384, 521
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
//
// The keyPair field is populated when:
//   - Key is generated with GenerateXXXKey() (exported generation)
//   - Key is imported with ImportXXXKey() (we have the private key)
//
// The keyPair field is nil when:
//   - Key is created with CreateXXXKey() (internal generation in OpenBao)
//   - Key is retrieved with GetXXXKey() (only metadata available)
type KeyClient[K keypair.KeyPair] struct {
	client  *Client
	keyInfo *KeyInfo
	keyPair K // Only set when key was generated/imported with private key material
}

// KeyInfo returns the key metadata.
func (kc *KeyClient[K]) KeyInfo() *KeyInfo {
	return kc.keyInfo
}

// KeyPair returns the cached key pair if available.
// Returns an error if the key pair is not cached (e.g., key was created with CreateXXXKey).
//
// The key pair is available when:
//   - Key was generated with GenerateXXXKey() (exported generation)
//   - Key was imported with ImportXXXKey()
//
// The key pair is NOT available when:
//   - Key was created with CreateXXXKey() (internal generation)
//   - Key was retrieved with GetXXXKey() (only metadata retrieved)
//
// Example:
//
//	keyClient, err := client.GenerateRSAKey(ctx, &GenerateKeyOptions{...})
//	keyPair, err := keyClient.KeyPair()  // Returns the keypair
//	// Use keyPair.PrivateKey, keyPair.PublicKey
func (kc *KeyClient[K]) KeyPair() (K, error) {
	var zero K
	// Use reflection to check if keyPair is nil (handles typed nil properly)
	v := reflect.ValueOf(kc.keyPair)
	if !v.IsValid() || v.IsZero() {
		return zero, fmt.Errorf("bao: key pair not available (key was created internally or retrieved without private key)")
	}
	return kc.keyPair, nil
}

// HasKeyPair returns true if the key pair is cached and available.
// This is a convenience method to check availability without handling errors.
//
// Example:
//
//	keyClient, err := client.CreateRSAKey(ctx, &GenerateKeyOptions{...})
//	if keyClient.HasKeyPair() {
//	    keyPair, _ := keyClient.KeyPair()
//	    // Use the keypair
//	} else {
//	    // Key is managed internally by OpenBao
//	}
func (kc *KeyClient[K]) HasKeyPair() bool {
	v := reflect.ValueOf(kc.keyPair)
	return v.IsValid() && !v.IsZero()
}

// Delete deletes this key from OpenBao.
//
// Example:
//
//	rsaKeys, _ := client.GetRSAKey(ctx, "key-id")
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

// IssueCertificate issues a certificate using this key.
// This is a convenience method that links KeyClient with CertificateClient operations.
//
// The key must exist in OpenBao (KeyInfo().KeyID must be available).
// The returned CertificateClient does NOT have a cached key pair (key stays in OpenBao).
//
// Example:
//
//	keyClient, _ := client.GenerateRSAKey(ctx, &GenerateKeyOptions{KeyName: "my-key"})
//	certClient, err := keyClient.IssueCertificate(ctx, "web-server", &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    TTL:        "720h",
//	})
//	cert := certClient.Certificate()
func (kc *KeyClient[K]) IssueCertificate(ctx context.Context, role string, opts *GenerateCertificateOptions) (*CertificateClient[K], error) {
	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return nil, fmt.Errorf("bao: key info not available")
	}

	keyRef := kc.keyInfo.KeyID
	return issueCertificateWithKeyRef[K](ctx, kc.client, role, keyRef, opts)
}

// SignCSR signs a CSR using this key.
// This is a convenience method for signing CSRs with a specific key from KeyClient.
//
// Example:
//
//	keyClient, _ := client.GetRSAKey(ctx, "my-ca-key")
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{...})
//	certificate, err := keyClient.SignCSR(ctx, "web-server", csr, &SignCertificateOptions{
//	    TTL: "8760h",
//	})
func (kc *KeyClient[K]) SignCSR(ctx context.Context, role string, csr *cert.CertificateSigningRequest, opts *SignCertificateOptions) (*cert.Certificate, error) {
	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return nil, fmt.Errorf("bao: key info not available")
	}

	keyRef := kc.keyInfo.KeyID
	return kc.client.SignCSRWithKeyRef(ctx, role, csr, keyRef, opts)
}

// SignVerbatim signs a CSR verbatim using this key.
// This bypasses role constraints and signs the CSR as-is.
//
// Example:
//
//	keyClient, _ := client.GetRSAKey(ctx, "my-ca-key")
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{...})
//	certificate, err := keyClient.SignVerbatim(ctx, csr, &SignVerbatimOptions{
//	    TTL: "8760h",
//	})
func (kc *KeyClient[K]) SignVerbatim(ctx context.Context, csr *cert.CertificateSigningRequest, opts *SignVerbatimOptions) (*cert.Certificate, error) {
	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return nil, fmt.Errorf("bao: key info not available")
	}

	keyRef := kc.keyInfo.KeyID
	return kc.client.SignVerbatimWithKeyRef(ctx, csr, keyRef, opts)
}

// GetIssuers returns all issuers that use this key.
// This enables navigation from KeyClient to IssuerClient.
//
// Example:
//
//	keyClient, _ := client.GetRSAKey(ctx, "my-key")
//	issuers, err := keyClient.GetIssuers(ctx)
//	for _, issuer := range issuers {
//	    fmt.Printf("Issuer: %s (ID: %s)\n", issuer.Name(), issuer.ID())
//	}
func (kc *KeyClient[K]) GetIssuers(ctx context.Context) ([]*IssuerClient, error) {
	if kc.keyInfo == nil || kc.keyInfo.KeyID == "" {
		return nil, fmt.Errorf("bao: key info not available")
	}

	// List all issuers
	issuerRefs, err := kc.client.ListIssuers(ctx)
	if err != nil {
		return nil, fmt.Errorf("bao: list issuers: %w", err)
	}

	// Filter issuers that use this key
	var result []*IssuerClient
	for _, issuerRef := range issuerRefs {
		issuer, err := kc.client.GetIssuer(ctx, issuerRef)
		if err != nil {
			continue // Skip issuers we can't access
		}
		if issuer.KeyID() == kc.keyInfo.KeyID {
			result = append(result, issuer)
		}
	}

	return result, nil
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

// GenerateRSAKey generates an RSA key and returns a KeyClient with the key pair cached.
// The key is also stored in OpenBao for future use.
// Access the keypair using keyClient.KeyPair().
//
// Example:
//
//	keyClient, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-rsa-key",
//	    KeyBits: 2048,
//	})
//	keyPair, err := keyClient.KeyPair()  // Get the cached keypair
//	// Use keyPair.PrivateKey, keyPair.PublicKey immediately
func (c *Client) GenerateRSAKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyClient[*algo.RSAKeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "rsa"
	if opts.KeyBits == 0 {
		opts.KeyBits = 2048
	}
	return generateKeyExported[*algo.RSAKeyPair](ctx, c, opts)
}

// CreateRSAKey creates an RSA key in OpenBao without returning the private key.
// The key is stored securely in OpenBao and cannot be retrieved later.
// Use this when you want OpenBao to manage the key internally (e.g., for signing operations).
//
// Example:
//
//	keyClient, err := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-managed-rsa-key",
//	    KeyBits: 2048,
//	})
//	// Key is stored in OpenBao, use keyClient for operations
func (c *Client) CreateRSAKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyClient[*algo.RSAKeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "rsa"
	if opts.KeyBits == 0 {
		opts.KeyBits = 2048
	}
	return generateKeyInternal[*algo.RSAKeyPair](ctx, c, opts)
}

// GenerateECDSAKey generates an ECDSA key and returns a KeyClient with the key pair cached.
// The key is also stored in OpenBao for future use.
// Access the keypair using keyClient.KeyPair().
//
// Example:
//
//	keyClient, err := client.GenerateECDSAKey(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-ec-key",
//	    KeyBits: 256,
//	})
//	keyPair, err := keyClient.KeyPair()  // Get the cached keypair
func (c *Client) GenerateECDSAKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyClient[*algo.ECDSAKeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "ec"
	if opts.KeyBits == 0 {
		opts.KeyBits = 256
	}
	return generateKeyExported[*algo.ECDSAKeyPair](ctx, c, opts)
}

// CreateECDSAKey creates an ECDSA key in OpenBao without returning the private key.
// The key is stored securely in OpenBao and cannot be retrieved later.
//
// Example:
//
//	keyClient, err := client.CreateECDSAKey(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-managed-ec-key",
//	    KeyBits: 256,
//	})
func (c *Client) CreateECDSAKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyClient[*algo.ECDSAKeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "ec"
	if opts.KeyBits == 0 {
		opts.KeyBits = 256
	}
	return generateKeyInternal[*algo.ECDSAKeyPair](ctx, c, opts)
}

// GenerateEd25519Key generates an Ed25519 key and returns a KeyClient with the key pair cached.
// The key is also stored in OpenBao for future use.
// Access the keypair using keyClient.KeyPair().
//
// Example:
//
//	keyClient, err := client.GenerateEd25519Key(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-ed25519-key",
//	})
//	keyPair, err := keyClient.KeyPair()  // Get the cached keypair
func (c *Client) GenerateEd25519Key(ctx context.Context, opts *GenerateKeyOptions) (*KeyClient[*algo.Ed25519KeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "ed25519"
	return generateKeyExported[*algo.Ed25519KeyPair](ctx, c, opts)
}

// CreateEd25519Key creates an Ed25519 key in OpenBao without returning the private key.
// The key is stored securely in OpenBao and cannot be retrieved later.
//
// Example:
//
//	keyClient, err := client.CreateEd25519Key(ctx, &bao.GenerateKeyOptions{
//	    KeyName: "my-managed-ed25519-key",
//	})
func (c *Client) CreateEd25519Key(ctx context.Context, opts *GenerateKeyOptions) (*KeyClient[*algo.Ed25519KeyPair], error) {
	if opts == nil {
		opts = &GenerateKeyOptions{}
	}
	opts.KeyType = "ed25519"
	return generateKeyInternal[*algo.Ed25519KeyPair](ctx, c, opts)
}

// generateKeyInternal is the internal implementation for generating non-exported keys.
// Keys are stored in OpenBao and private key material is not returned.
func generateKeyInternal[K keypair.KeyPair](ctx context.Context, client *Client, opts *GenerateKeyOptions) (*KeyClient[K], error) {
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

	// Use SDK to generate internal key
	path := fmt.Sprintf("%s/keys/generate/internal", client.config.Mount)
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

// generateKeyExported is the internal implementation for generating exported keys.
// Returns a KeyClient with the private key cached for immediate use.
func generateKeyExported[K keypair.KeyPair](ctx context.Context, client *Client, opts *GenerateKeyOptions) (*KeyClient[K], error) {
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

	// Use SDK to generate exported key
	path := fmt.Sprintf("%s/keys/generate/exported", client.config.Mount)
	secret, err := client.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: generate key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: generate key: empty response")
	}

	// Extract metadata
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

	keyInfo := &KeyInfo{
		KeyID:   keyID,
		KeyName: keyName,
		KeyType: keyType,
		KeyBits: keyBits,
	}

	// Extract and parse private key
	privateKeyPEM, ok := secret.Data["private_key"].(string)
	if !ok || privateKeyPEM == "" {
		return nil, fmt.Errorf("bao: generate key: no private key in response")
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("bao: generate key: failed to decode PEM")
	}

	// Parse based on key type
	switch keyType {
	case "rsa":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("bao: parse RSA key: %w", err)
			}
			var ok bool
			privateKey, ok = pkcs8Key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("bao: expected RSA key, got %T", pkcs8Key)
			}
		}
		keyPair := &algo.RSAKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}
		return &KeyClient[K]{
			client:  client,
			keyInfo: keyInfo,
			keyPair: any(keyPair).(K),
		}, nil

	case "ec":
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("bao: parse ECDSA key: %w", err)
			}
			var ok bool
			privateKey, ok = pkcs8Key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("bao: expected ECDSA key, got %T", pkcs8Key)
			}
		}
		keyPair := &algo.ECDSAKeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}
		return &KeyClient[K]{
			client:  client,
			keyInfo: keyInfo,
			keyPair: any(keyPair).(K),
		}, nil

	case "ed25519":
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bao: parse Ed25519 key: %w", err)
		}
		privateKey, ok := pkcs8Key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("bao: expected Ed25519 key, got %T", pkcs8Key)
		}
		publicKey := privateKey.Public().(ed25519.PublicKey)
		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
		return &KeyClient[K]{
			client:  client,
			keyInfo: keyInfo,
			keyPair: any(keyPair).(K),
		}, nil

	default:
		return nil, fmt.Errorf("bao: unsupported key type: %s", keyType)
	}
}

// ============================================================================
// Import Key - Entry Points
// ============================================================================

// ImportRSAKey imports an RSA key pair into OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	rsaKeys, err := client.ImportRSAKey(ctx, rsaKeyPair, &bao.ImportKeyOptions{
//	    KeyName: "imported-rsa-key",
//	})
func (c *Client) ImportRSAKey(ctx context.Context, kp *algo.RSAKeyPair, opts *ImportKeyOptions) (*KeyClient[*algo.RSAKeyPair], error) {
	return importKeyTyped[*algo.RSAKeyPair](ctx, c, kp, opts)
}

// ImportECDSAKey imports an ECDSA key pair into OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	ecKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	ecKeys, err := client.ImportECDSAKey(ctx, ecKeyPair, &bao.ImportKeyOptions{
//	    KeyName: "imported-ec-key",
//	})
func (c *Client) ImportECDSAKey(ctx context.Context, kp *algo.ECDSAKeyPair, opts *ImportKeyOptions) (*KeyClient[*algo.ECDSAKeyPair], error) {
	return importKeyTyped[*algo.ECDSAKeyPair](ctx, c, kp, opts)
}

// ImportEd25519Key imports an Ed25519 key pair into OpenBao and returns a type-safe KeyClient.
//
// Example:
//
//	edKeyPair, _ := algo.GenerateEd25519KeyPair()
//	edKeys, err := client.ImportEd25519Key(ctx, edKeyPair, &bao.ImportKeyOptions{
//	    KeyName: "imported-ed25519-key",
//	})
func (c *Client) ImportEd25519Key(ctx context.Context, kp *algo.Ed25519KeyPair, opts *ImportKeyOptions) (*KeyClient[*algo.Ed25519KeyPair], error) {
	return importKeyTyped[*algo.Ed25519KeyPair](ctx, c, kp, opts)
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
		keyPair: kp, // Store the imported keypair
	}, nil
}

// ============================================================================
// Get Key - Entry Points
// ============================================================================

// GetRSAKey retrieves an RSA key reference from OpenBao and returns a type-safe KeyClient.
// Note: This only retrieves metadata. The private key material is not available
// unless the key was originally generated with GenerateRSAKey or imported with ImportRSAKey.
//
// Example:
//
//	rsaKeys, err := client.GetRSAKey(ctx, "rsa-key-id")
//	// Use rsaKeys for operations like UpdateName(), Delete()
func (c *Client) GetRSAKey(ctx context.Context, keyRef string) (*KeyClient[*algo.RSAKeyPair], error) {
	return getKeyTyped[*algo.RSAKeyPair](ctx, c, keyRef, "rsa")
}

// GetECDSAKey retrieves an ECDSA key reference from OpenBao and returns a type-safe KeyClient.
// Note: This only retrieves metadata. The private key material is not available
// unless the key was originally generated with GenerateECDSAKey or imported with ImportECDSAKey.
//
// Example:
//
//	ecKeys, err := client.GetECDSAKey(ctx, "ec-key-id")
//	// Use ecKeys for operations like UpdateName(), Delete()
func (c *Client) GetECDSAKey(ctx context.Context, keyRef string) (*KeyClient[*algo.ECDSAKeyPair], error) {
	return getKeyTyped[*algo.ECDSAKeyPair](ctx, c, keyRef, "ec")
}

// GetEd25519Key retrieves an Ed25519 key reference from OpenBao and returns a type-safe KeyClient.
// Note: This only retrieves metadata. The private key material is not available
// unless the key was originally generated with GenerateEd25519Key or imported with ImportEd25519Key.
//
// Example:
//
//	edKeys, err := client.GetEd25519Key(ctx, "ed25519-key-id")
//	// Use edKeys for operations like UpdateName(), Delete()
func (c *Client) GetEd25519Key(ctx context.Context, keyRef string) (*KeyClient[*algo.Ed25519KeyPair], error) {
	return getKeyTyped[*algo.Ed25519KeyPair](ctx, c, keyRef, "ed25519")
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
