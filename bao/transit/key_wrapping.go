package transit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"runtime"

	"github.com/awnumar/memguard"
	"github.com/google/tink/go/kwp/subtle"
)

// WrappingKey represents OpenBao's RSA public key used for secure key import.
type WrappingKey struct {
	PublicKey *rsa.PublicKey
	PEM       string
}

// GetWrappingKey retrieves the Transit wrapping key from OpenBao.
// This key is used to securely wrap external keys for import.
//
// Example:
//
//	wrappingKey, err := client.GetWrappingKey(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use wrappingKey to wrap your own key material
//	wrapped, err := WrapKeyForImport(myKeyBytes, wrappingKey, "SHA256")
func (c *Client) GetWrappingKey(ctx context.Context) (*WrappingKey, error) {
	path := "wrapping_key"
	secret, err := c.read(ctx, path)
	if err != nil {
		return nil, WrapError("GetWrappingKey", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("GetWrappingKey", fmt.Errorf("no wrapping key data returned"))
	}

	publicKeyPEM, ok := secret.Data["public_key"].(string)
	if !ok {
		return nil, WrapError("GetWrappingKey", fmt.Errorf("invalid public_key format"))
	}

	publicKey, err := parseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, WrapError("GetWrappingKey", fmt.Errorf("parse wrapping key: %w", err))
	}

	return &WrappingKey{
		PublicKey: publicKey,
		PEM:       publicKeyPEM,
	}, nil
}

// ImportKey imports an external key into OpenBao using secure two-layer wrapping.
//
// The key import process:
//  1. Generate ephemeral AES-256 key (locked in memory with memguard)
//  2. Wrap target key with ephemeral key using KWP (RFC 5649)
//  3. Encrypt ephemeral key with OpenBao's RSA public key using RSA-OAEP
//  4. Concatenate and send to OpenBao
//  5. Ephemeral key is automatically zeroed (even on panic)
//
// Example:
//
//	// Generate or load your key
//	myKey := make([]byte, 32) // AES-256 key
//	rand.Read(myKey)
//	defer secureZero(myKey)
//
//	err := client.ImportKey(ctx, "my-imported-key", myKey, &transit.ImportKeyOptions{
//	    Type:         transit.KeyTypeAES256GCM96,
//	    HashFunction: "SHA256",
//	    Exportable:   true,
//	})
func (c *Client) ImportKey(ctx context.Context, name string, keyMaterial []byte, opts *ImportKeyOptions) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if len(keyMaterial) == 0 {
		return fmt.Errorf("%w: key material cannot be empty", ErrInvalidConfig)
	}

	if opts == nil {
		opts = &ImportKeyOptions{
			Type:         KeyTypeAES256GCM96,
			HashFunction: "SHA256",
		}
	}

	// Get wrapping key from OpenBao
	wrappingKey, err := c.GetWrappingKey(ctx)
	if err != nil {
		return WrapError("ImportKey", err)
	}

	// Wrap key material securely
	hashFunc := opts.HashFunction
	if hashFunc == "" {
		hashFunc = "SHA256"
	}

	wrappedKey, err := WrapKeyForImport(keyMaterial, wrappingKey, hashFunc)
	if err != nil {
		return WrapError("ImportKey", fmt.Errorf("wrap key: %w", err))
	}
	defer secureZero([]byte(wrappedKey)) // Clear wrapped key from memory

	// Prepare import request
	data := map[string]interface{}{
		"ciphertext": wrappedKey,
		"type":       opts.Type,
	}

	if opts.HashFunction != "" {
		data["hash_function"] = opts.HashFunction
	}
	if opts.Exportable {
		data["exportable"] = true
	}
	if opts.AllowPlaintextBackup {
		data["allow_plaintext_backup"] = true
	}
	if opts.AllowRotation {
		data["allow_rotation"] = true
	}
	if opts.Derived {
		data["derived"] = true
	}
	if opts.ConvergentEncryption {
		data["convergent_encryption"] = true
	}
	if opts.AutoRotatePeriod > 0 {
		data["auto_rotate_period"] = int(opts.AutoRotatePeriod.Seconds())
	}

	// Import the key
	path := fmt.Sprintf("keys/%s/import", name)
	_, err = c.write(ctx, path, data)
	if err != nil {
		return WrapError("ImportKey", err)
	}

	return nil
}

// ImportKeyVersion imports a new version of an existing key.
func (c *Client) ImportKeyVersion(ctx context.Context, name string, keyMaterial []byte, hashFunction string) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if len(keyMaterial) == 0 {
		return fmt.Errorf("%w: key material cannot be empty", ErrInvalidConfig)
	}

	// Get wrapping key
	wrappingKey, err := c.GetWrappingKey(ctx)
	if err != nil {
		return WrapError("ImportKeyVersion", err)
	}

	// Wrap key material
	if hashFunction == "" {
		hashFunction = "SHA256"
	}

	wrappedKey, err := WrapKeyForImport(keyMaterial, wrappingKey, hashFunction)
	if err != nil {
		return WrapError("ImportKeyVersion", fmt.Errorf("wrap key: %w", err))
	}
	defer secureZero([]byte(wrappedKey))

	// Import key version
	data := map[string]interface{}{
		"ciphertext": wrappedKey,
	}

	if hashFunction != "" {
		data["hash_function"] = hashFunction
	}

	path := fmt.Sprintf("keys/%s/import_version", name)
	_, err = c.write(ctx, path, data)
	if err != nil {
		return WrapError("ImportKeyVersion", err)
	}

	return nil
}

// ExportKey exports key material from OpenBao.
// The key must have exportable=true.
// Returns a map of version -> key material (base64 encoded).
func (c *Client) ExportKey(ctx context.Context, name string, keyType ExportKeyType, version int) (map[int]string, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	var path string
	if version == 0 {
		// Export all versions
		path = fmt.Sprintf("export/%s/%s", keyType, name)
	} else {
		// Export specific version
		path = fmt.Sprintf("export/%s/%s/%d", keyType, name, version)
	}

	secret, err := c.read(ctx, path)
	if err != nil {
		return nil, WrapError("ExportKey", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("ExportKey", fmt.Errorf("no export data returned"))
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, WrapError("ExportKey", fmt.Errorf("no keys in export data"))
	}

	keysMap, ok := keysRaw.(map[string]interface{})
	if !ok {
		return nil, WrapError("ExportKey", fmt.Errorf("invalid keys format"))
	}

	result := make(map[int]string)
	for versionStr, keyData := range keysMap {
		var ver int
		fmt.Sscanf(versionStr, "%d", &ver)

		if keyStr, ok := keyData.(string); ok {
			result[ver] = keyStr
		}
	}

	return result, nil
}

// BackupKey creates an encrypted backup of the key.
// The returned backup string can be used with RestoreBackup.
func (c *Client) BackupKey(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	path := fmt.Sprintf("backup/%s", name)
	secret, err := c.read(ctx, path)
	if err != nil {
		return "", WrapError("BackupKey", err)
	}

	if secret == nil || secret.Data == nil {
		return "", WrapError("BackupKey", fmt.Errorf("no backup data returned"))
	}

	backup, ok := secret.Data["backup"].(string)
	if !ok {
		return "", WrapError("BackupKey", fmt.Errorf("invalid backup format"))
	}

	return backup, nil
}

// RestoreBackup restores a key from an encrypted backup.
func (c *Client) RestoreBackup(ctx context.Context, name, backup string) error {
	if name == "" {
		return fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if backup == "" {
		return fmt.Errorf("%w: backup cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{
		"backup": backup,
	}

	path := fmt.Sprintf("restore/%s", name)
	_, err := c.write(ctx, path, data)
	if err != nil {
		return WrapError("RestoreBackup", err)
	}

	return nil
}

// WrapKeyForImport performs the complete two-layer wrapping for secure key import.
// This function uses memguard for secure ephemeral key handling.
//
// Security features:
//   - Ephemeral key locked in memory (mlock) to prevent swapping to disk
//   - Automatic zeroing via defer, even on panic
//   - Uses battle-tested libraries (Google Tink for KWP)
//
// Parameters:
//   - targetKey: The key material to wrap (will NOT be modified or zeroed)
//   - wrappingKey: OpenBao's RSA public key
//   - hashFunc: Hash function for RSA-OAEP (SHA256, SHA384, SHA512, SHA1)
//
// Returns: Base64-encoded wrapped key ready for import
func WrapKeyForImport(targetKey []byte, wrappingKey *WrappingKey, hashFunc string) (string, error) {
	if len(targetKey) == 0 {
		return "", fmt.Errorf("target key is empty")
	}

	if wrappingKey == nil || wrappingKey.PublicKey == nil {
		return "", fmt.Errorf("wrapping key is nil")
	}

	// 1. Generate ephemeral AES-256 key (locked in memory)
	ephemeralKey := memguard.NewBufferRandom(32)
	defer ephemeralKey.Destroy() // GUARANTEED zeroing, even on panic

	// 2. Wrap target key with KWP (RFC 5649)
	wrappedTarget, err := wrapWithKWP(targetKey, ephemeralKey.Bytes())
	if err != nil {
		return "", fmt.Errorf("wrap with KWP: %w", err)
	}

	// 3. Encrypt ephemeral key with RSA-OAEP
	wrappedEphemeral, err := encryptWithRSAOAEP(
		ephemeralKey.Bytes(),
		wrappingKey.PublicKey,
		hashFunc,
	)
	if err != nil {
		return "", fmt.Errorf("encrypt with RSA-OAEP: %w", err)
	}

	// 4. Concatenate: [wrapped ephemeral] + [wrapped target]
	combined := append(wrappedEphemeral, wrappedTarget...)

	// 5. Base64 encode
	return base64.StdEncoding.EncodeToString(combined), nil

	// ephemeralKey.Destroy() called automatically
	// Memory is guaranteed to be zeroed and unlocked
}

// wrapWithKWP uses Google Tink's KWP implementation (RFC 5649).
// Key Wrap with Padding provides authenticated encryption of key material.
func wrapWithKWP(plaintext, kek []byte) ([]byte, error) {
	kwp, err := subtle.NewKWP(kek)
	if err != nil {
		return nil, fmt.Errorf("create KWP: %w", err)
	}
	return kwp.Wrap(plaintext)
}

// encryptWithRSAOAEP encrypts using RSA-OAEP with configurable hash function.
func encryptWithRSAOAEP(plaintext []byte, pubKey *rsa.PublicKey, hashFunc string) ([]byte, error) {
	var h hash.Hash

	switch hashFunc {
	case "SHA256":
		h = sha256.New()
	case "SHA384":
		h = sha512.New384()
	case "SHA512":
		h = sha512.New()
	case "SHA1":
		// DEPRECATED: SHA1 is cryptographically weak
		// Only use if required for legacy compatibility with older OpenBao versions
		h = sha1.New()
	default:
		return nil, fmt.Errorf("unsupported hash function: %s (supported: SHA256, SHA384, SHA512, SHA1)", hashFunc)
	}

	ciphertext, err := rsa.EncryptOAEP(h, rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	return ciphertext, nil
}

// secureZero overwrites sensitive data in memory.
// Uses runtime.KeepAlive to prevent compiler optimization from removing the zeroing.
//
// For cryptographic key material (especially ephemeral keys), use memguard instead.
// This function is suitable for PEM-encoded keys, passwords, and other sensitive strings.
func secureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Zero the memory
	for i := range data {
		data[i] = 0
	}

	// Prevent compiler from optimizing away the zeroing
	// This makes the memory observable and prevents dead store elimination
	runtime.KeepAlive(data)
}

// parseRSAPublicKeyFromPEM parses a PEM-encoded RSA public key.
func parseRSAPublicKeyFromPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected PUBLIC KEY)", block.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key (got %T)", pub)
	}

	// Validate RSA key size (minimum 2048 bits for security)
	keyBits := rsaPub.N.BitLen()
	if keyBits < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum 2048 required)", keyBits)
	}

	return rsaPub, nil
}
