package transit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// KeyClient provides type-safe operations for a specific Transit key.
// The generic type parameter T ensures compile-time type safety for key operations.
//
// Example usage:
//
//	// Create a type-safe AES-256 key client
//	keyClient, err := client.CreateAES256Key(ctx, "my-key", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Encrypt data (type-safe - only works with encryption keys)
//	result, err := keyClient.Encrypt(ctx, []byte("secret"), nil)
type KeyClient[T KeyType] struct {
	client  *Client
	keyName string
	keyType T
}

// CreateKeyOptions configures options when creating a new Transit key.
type CreateKeyOptions struct {
	// Derived enables key derivation for multi-tenant scenarios.
	// When true, each encryption operation can use a unique context to derive a sub-key.
	Derived bool

	// Exportable allows the key to be exported from OpenBao.
	// WARNING: Exportable keys are less secure. Only enable when necessary for BYOK or backup.
	Exportable bool

	// AllowPlaintextBackup allows backing up the key in plaintext.
	// WARNING: This is highly insecure and should only be used in dev/testing.
	AllowPlaintextBackup bool

	// ConvergentEncryption enables deterministic encryption.
	// Same plaintext + context always produces the same ciphertext.
	// Requires Derived=true.
	ConvergentEncryption bool

	// AutoRotatePeriod enables automatic key rotation.
	// Example: 365 * 24 * time.Hour for yearly rotation.
	AutoRotatePeriod time.Duration
}

// UpdateKeyOptions configures updates to an existing key's configuration.
type UpdateKeyOptions struct {
	// MinDecryptionVersion sets the minimum key version that can be used for decryption.
	// Versions below this cannot decrypt data.
	MinDecryptionVersion *int

	// MinEncryptionVersion sets the minimum key version used for encryption.
	// New encryptions will use at least this version.
	MinEncryptionVersion *int

	// DeletionAllowed enables/disables key deletion.
	DeletionAllowed *bool

	// Exportable enables/disables key export.
	// WARNING: Cannot be set to false once enabled.
	Exportable *bool

	// AllowPlaintextBackup enables/disables plaintext backup.
	// WARNING: Cannot be set to false once enabled.
	AllowPlaintextBackup *bool

	// AutoRotatePeriod updates the automatic rotation period.
	// Set to 0 to disable auto-rotation.
	AutoRotatePeriod *time.Duration
}

// ImportKeyOptions configures options when importing an external key.
type ImportKeyOptions struct {
	// Type is the key type (aes256-gcm96, rsa-2048, etc.)
	Type string

	// HashFunction for RSA-OAEP wrapping (SHA256, SHA384, SHA512, SHA1)
	// Default: SHA256
	HashFunction string

	// Exportable allows the imported key to be exported.
	Exportable bool

	// AllowPlaintextBackup allows backing up in plaintext.
	AllowPlaintextBackup bool

	// AllowRotation enables rotation of imported keys.
	AllowRotation bool

	// Derived enables key derivation.
	Derived bool

	// ConvergentEncryption enables deterministic encryption.
	ConvergentEncryption bool

	// AutoRotatePeriod enables automatic rotation.
	AutoRotatePeriod time.Duration
}

// ExportKeyType specifies which type of key material to export.
type ExportKeyType string

const (
	// ExportEncryptionKey exports the encryption key.
	ExportEncryptionKey ExportKeyType = "encryption-key"

	// ExportSigningKey exports the signing key.
	ExportSigningKey ExportKeyType = "signing-key"

	// ExportHMACKey exports the HMAC key.
	ExportHMACKey ExportKeyType = "hmac-key"
)

// CreateAES256Key creates a new AES-256-GCM key and returns a type-safe client.
//
// Example:
//
//	keyClient, err := client.CreateAES256Key(ctx, "my-encryption-key", &transit.CreateKeyOptions{
//	    Derived:    true,
//	    Exportable: false,
//	})
func (c *Client) CreateAES256Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeAES256], error) {
	if err := c.createKey(ctx, name, KeyTypeAES256GCM96, opts); err != nil {
		return nil, err
	}
	return &KeyClient[KeyTypeAES256]{
		client:  c,
		keyName: name,
		keyType: KeyTypeAES256{},
	}, nil
}

// CreateAES128Key creates a new AES-128-GCM key and returns a type-safe client.
func (c *Client) CreateAES128Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeAES128], error) {
	if err := c.createKey(ctx, name, KeyTypeAES128GCM96, opts); err != nil {
		return nil, err
	}
	return &KeyClient[KeyTypeAES128]{
		client:  c,
		keyName: name,
		keyType: KeyTypeAES128{},
	}, nil
}

// CreateChaCha20Key creates a new ChaCha20-Poly1305 key and returns a type-safe client.
func (c *Client) CreateChaCha20Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeChaCha20], error) {
	if err := c.createKey(ctx, name, KeyTypeChaCha20Poly1305, opts); err != nil {
		return nil, err
	}
	return &KeyClient[KeyTypeChaCha20]{
		client:  c,
		keyName: name,
		keyType: KeyTypeChaCha20{},
	}, nil
}

// CreateXChaCha20Key creates a new XChaCha20-Poly1305 key and returns a type-safe client.
func (c *Client) CreateXChaCha20Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeXChaCha20], error) {
	if err := c.createKey(ctx, name, KeyTypeXChaCha20Poly1305, opts); err != nil {
		return nil, err
	}
	return &KeyClient[KeyTypeXChaCha20]{
		client:  c,
		keyName: name,
		keyType: KeyTypeXChaCha20{},
	}, nil
}

// CreateRSA2048Key creates a new RSA-2048 key and returns a type-safe client.
func (c *Client) CreateRSA2048Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[RSA2048], error) {
	if err := c.createKey(ctx, name, KeyTypeRSA2048, opts); err != nil {
		return nil, err
	}
	return &KeyClient[RSA2048]{
		client:  c,
		keyName: name,
		keyType: RSA2048{},
	}, nil
}

// CreateRSA3072Key creates a new RSA-3072 key and returns a type-safe client.
func (c *Client) CreateRSA3072Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[RSA3072], error) {
	if err := c.createKey(ctx, name, KeyTypeRSA3072, opts); err != nil {
		return nil, err
	}
	return &KeyClient[RSA3072]{
		client:  c,
		keyName: name,
		keyType: RSA3072{},
	}, nil
}

// CreateRSA4096Key creates a new RSA-4096 key and returns a type-safe client.
func (c *Client) CreateRSA4096Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[RSA4096], error) {
	if err := c.createKey(ctx, name, KeyTypeRSA4096, opts); err != nil {
		return nil, err
	}
	return &KeyClient[RSA4096]{
		client:  c,
		keyName: name,
		keyType: RSA4096{},
	}, nil
}

// CreateECDSAP256Key creates a new ECDSA P-256 signing key and returns a type-safe client.
func (c *Client) CreateECDSAP256Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[ECDSAP256], error) {
	if err := c.createKey(ctx, name, KeyTypeECDSAP256, opts); err != nil {
		return nil, err
	}
	return &KeyClient[ECDSAP256]{
		client:  c,
		keyName: name,
		keyType: ECDSAP256{},
	}, nil
}

// CreateECDSAP384Key creates a new ECDSA P-384 signing key and returns a type-safe client.
func (c *Client) CreateECDSAP384Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[ECDSAP384], error) {
	if err := c.createKey(ctx, name, KeyTypeECDSAP384, opts); err != nil {
		return nil, err
	}
	return &KeyClient[ECDSAP384]{
		client:  c,
		keyName: name,
		keyType: ECDSAP384{},
	}, nil
}

// CreateECDSAP521Key creates a new ECDSA P-521 signing key and returns a type-safe client.
func (c *Client) CreateECDSAP521Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[ECDSAP521], error) {
	if err := c.createKey(ctx, name, KeyTypeECDSAP521, opts); err != nil {
		return nil, err
	}
	return &KeyClient[ECDSAP521]{
		client:  c,
		keyName: name,
		keyType: ECDSAP521{},
	}, nil
}

// CreateEd25519Key creates a new Ed25519 signing key and returns a type-safe client.
func (c *Client) CreateEd25519Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[Ed25519], error) {
	if err := c.createKey(ctx, name, KeyTypeEd25519, opts); err != nil {
		return nil, err
	}
	return &KeyClient[Ed25519]{
		client:  c,
		keyName: name,
		keyType: Ed25519{},
	}, nil
}

// CreateHMACKey creates a new HMAC key and returns a type-safe client.
func (c *Client) CreateHMACKey(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[HMAC], error) {
	if err := c.createKey(ctx, name, KeyTypeHMAC, opts); err != nil {
		return nil, err
	}
	return &KeyClient[HMAC]{
		client:  c,
		keyName: name,
		keyType: HMAC{},
	}, nil
}

// createKey is the internal method that creates a key in OpenBao.
func (c *Client) createKey(ctx context.Context, name, keyType string, opts *CreateKeyOptions) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{
		"type": keyType,
	}

	if opts != nil {
		if opts.Derived {
			data["derived"] = true
		}
		if opts.Exportable {
			data["exportable"] = true
		}
		if opts.AllowPlaintextBackup {
			data["allow_plaintext_backup"] = true
		}
		if opts.ConvergentEncryption {
			data["convergent_encryption"] = true
			// Convergent encryption requires derived=true
			data["derived"] = true
		}
		if opts.AutoRotatePeriod > 0 {
			data["auto_rotate_period"] = int(opts.AutoRotatePeriod.Seconds())
		}
	}

	path := fmt.Sprintf("keys/%s", name)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		return WrapError("CreateKey", err)
	}

	if secret != nil && len(secret.Warnings) > 0 {
		// Log warnings if available
		// In production, this would use a logger
	}

	return nil
}

// GetKey retrieves information about an existing key.
// This method is not type-safe. Use GetAES256Key, GetRSA2048Key, etc. for type-safe access.
func (c *Client) GetKey(ctx context.Context, name string) (*KeyInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	path := fmt.Sprintf("keys/%s", name)
	secret, err := c.read(ctx, path)
	if err != nil {
		return nil, WrapError("GetKey", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("GetKey", ErrKeyNotFound)
	}

	return parseKeyInfo(name, secret.Data)
}

// GetAES256Key retrieves a type-safe client for an existing AES-256 key.
func (c *Client) GetAES256Key(ctx context.Context, name string) (*KeyClient[KeyTypeAES256], error) {
	keyInfo, err := c.GetKey(ctx, name)
	if err != nil {
		return nil, err
	}

	if keyInfo.Type != KeyTypeAES256GCM96 {
		return nil, fmt.Errorf("key %s is type %s, not aes256-gcm96", name, keyInfo.Type)
	}

	return &KeyClient[KeyTypeAES256]{
		client:  c,
		keyName: name,
		keyType: KeyTypeAES256{},
	}, nil
}

// Similar type-safe getters for other key types...

// UpdateKeyConfig updates the configuration of an existing key.
func (c *Client) UpdateKeyConfig(ctx context.Context, name string, opts *UpdateKeyOptions) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if opts == nil {
		return nil // Nothing to update
	}

	data := make(map[string]interface{})

	if opts.MinDecryptionVersion != nil {
		data["min_decryption_version"] = *opts.MinDecryptionVersion
	}
	if opts.MinEncryptionVersion != nil {
		data["min_encryption_version"] = *opts.MinEncryptionVersion
	}
	if opts.DeletionAllowed != nil {
		data["deletion_allowed"] = *opts.DeletionAllowed
	}
	if opts.Exportable != nil {
		data["exportable"] = *opts.Exportable
	}
	if opts.AllowPlaintextBackup != nil {
		data["allow_plaintext_backup"] = *opts.AllowPlaintextBackup
	}
	if opts.AutoRotatePeriod != nil {
		if *opts.AutoRotatePeriod == 0 {
			data["auto_rotate_period"] = 0
		} else {
			data["auto_rotate_period"] = int(opts.AutoRotatePeriod.Seconds())
		}
	}

	if len(data) == 0 {
		return nil // Nothing to update
	}

	path := fmt.Sprintf("keys/%s/config", name)
	_, err := c.write(ctx, path, data)
	if err != nil {
		return WrapError("UpdateKeyConfig", err)
	}

	return nil
}

// RotateKey rotates a key to a new version.
// This creates a new key version while keeping old versions available for decryption.
func (c *Client) RotateKey(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	path := fmt.Sprintf("keys/%s/rotate", name)
	_, err := c.write(ctx, path, nil)
	if err != nil {
		return WrapError("RotateKey", err)
	}

	return nil
}

// DeleteKey deletes a key from OpenBao.
// The key must have deletion_allowed set to true.
func (c *Client) DeleteKey(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	path := fmt.Sprintf("keys/%s", name)
	_, err := c.delete(ctx, path)
	if err != nil {
		return WrapError("DeleteKey", err)
	}

	return nil
}

// TrimKeyVersions removes old key versions.
// Versions below minVersion will be permanently deleted.
func (c *Client) TrimKeyVersions(ctx context.Context, name string, minVersion int) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if minVersion < 1 {
		return fmt.Errorf("minVersion must be >= 1, got %d", minVersion)
	}

	data := map[string]interface{}{
		"min_available_version": minVersion,
	}

	path := fmt.Sprintf("keys/%s/trim", name)
	_, err := c.write(ctx, path, data)
	if err != nil {
		return WrapError("TrimKeyVersions", err)
	}

	return nil
}

// ListKeys returns a list of all key names in the Transit engine.
func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	secret, err := c.list(ctx, "keys")
	if err != nil {
		return nil, WrapError("ListKeys", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return []string{}, nil
	}

	keysInterface, ok := keysRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys format")
	}

	keys := make([]string, 0, len(keysInterface))
	for _, k := range keysInterface {
		if keyStr, ok := k.(string); ok {
			keys = append(keys, keyStr)
		}
	}

	return keys, nil
}

// getInt safely extracts an integer from interface{}, handling multiple types.
func getInt(data map[string]interface{}, key string) int {
	val, ok := data[key]
	if !ok {
		return 0
	}

	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

// parseKeyInfo converts OpenBao API response to KeyInfo struct.
func parseKeyInfo(name string, data map[string]interface{}) (*KeyInfo, error) {
	keyInfo := &KeyInfo{
		Name: name,
		Keys: make(map[int]KeyVersion),
	}

	// Parse type
	if typeRaw, ok := data["type"].(string); ok {
		keyInfo.Type = typeRaw
	}

	// Parse boolean flags
	if val, ok := data["deletion_allowed"].(bool); ok {
		keyInfo.DeletionAllowed = val
	}
	if val, ok := data["derived"].(bool); ok {
		keyInfo.Derived = val
	}
	if val, ok := data["exportable"].(bool); ok {
		keyInfo.Exportable = val
	}
	if val, ok := data["allow_plaintext_backup"].(bool); ok {
		keyInfo.AllowPlaintextBackup = val
	}
	if val, ok := data["supports_encryption"].(bool); ok {
		keyInfo.SupportsEncryption = val
	}
	if val, ok := data["supports_decryption"].(bool); ok {
		keyInfo.SupportsDecryption = val
	}
	if val, ok := data["supports_signing"].(bool); ok {
		keyInfo.SupportsSigning = val
	}
	if val, ok := data["supports_derivation"].(bool); ok {
		keyInfo.SupportsDerivation = val
	}
	if val, ok := data["convergent_encryption"].(bool); ok {
		keyInfo.ConvergentEncryption = val
	}

	// Parse integer values using helper function
	keyInfo.LatestVersion = getInt(data, "latest_version")
	keyInfo.MinDecryptionVersion = getInt(data, "min_decryption_version")
	keyInfo.MinEncryptionVersion = getInt(data, "min_encryption_version")
	keyInfo.ConvergentVersion = getInt(data, "convergent_version")

	// Parse auto rotate period
	if period := getInt(data, "auto_rotate_period"); period > 0 {
		keyInfo.AutoRotatePeriod = time.Duration(period) * time.Second
	}

	// Parse key versions
	if keysRaw, ok := data["keys"].(map[string]interface{}); ok {
		for versionStr, versionData := range keysRaw {
			var version int
			fmt.Sscanf(versionStr, "%d", &version)

			if versionMap, ok := versionData.(map[string]interface{}); ok {
				keyVersion := KeyVersion{}

				if creationTimeStr, ok := versionMap["creation_time"].(string); ok {
					if t, err := time.Parse(time.RFC3339Nano, creationTimeStr); err == nil {
						keyVersion.CreationTime = t
					}
				}

				if pubKey, ok := versionMap["public_key"].(string); ok {
					keyVersion.PublicKey = pubKey
				}

				keyInfo.Keys[version] = keyVersion
			}
		}
	}

	return keyInfo, nil
}

// Name returns the key name.
func (kc *KeyClient[T]) Name() string {
	return kc.keyName
}

// Type returns the key type.
func (kc *KeyClient[T]) Type() T {
	return kc.keyType
}

// GetInfo retrieves the current key information.
func (kc *KeyClient[T]) GetInfo(ctx context.Context) (*KeyInfo, error) {
	return kc.client.GetKey(ctx, kc.keyName)
}

// Update updates the key configuration.
func (kc *KeyClient[T]) Update(ctx context.Context, opts *UpdateKeyOptions) error {
	return kc.client.UpdateKeyConfig(ctx, kc.keyName, opts)
}

// Rotate rotates the key to a new version.
func (kc *KeyClient[T]) Rotate(ctx context.Context) error {
	return kc.client.RotateKey(ctx, kc.keyName)
}

// Delete deletes the key from OpenBao.
func (kc *KeyClient[T]) Delete(ctx context.Context) error {
	return kc.client.DeleteKey(ctx, kc.keyName)
}

// TrimVersions removes old key versions below minVersion.
func (kc *KeyClient[T]) TrimVersions(ctx context.Context, minVersion int) error {
	return kc.client.TrimKeyVersions(ctx, kc.keyName, minVersion)
}
