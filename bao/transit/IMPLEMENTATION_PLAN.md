# OpenBao Transit Secrets Engine - Implementation Plan

**Package:** `github.com/jasoet/gopki/bao/transit`
**Reference:** [OpenBao Transit API Documentation](https://openbao.org/api-docs/secret/transit/)
**Pattern:** Based on `bao/pki` package architecture

---

## Overview

The Transit secrets engine implementation will provide **"Encryption as a Service"** capabilities, enabling applications to perform cryptographic operations without exposing key material. This package follows the same design patterns established in `bao/pki` for consistency and maintainability.

### Core Features
- ✅ Encryption/Decryption (symmetric & asymmetric)
- ✅ Digital Signatures (RSA, ECDSA, Ed25519)
- ✅ Key Management (create, rotate, import, export)
- ✅ HMAC generation and verification
- ✅ Cryptographic hashing
- ✅ Random bytes generation
- ✅ Data key generation (envelope encryption)
- ✅ Batch operations
- ✅ Key derivation (multi-tenant scenarios)
- ✅ Convergent encryption (deterministic)

---

## Phase 1: Core Infrastructure

### 1.1 Foundation Files

#### **File: `client.go`**
Main client for Transit operations, following `bao/pki/client.go` pattern.

**Type:**
```go
type Client struct {
    config *Config
    client *api.Client // OpenBao SDK client
}
```

**Functions:**
- `NewClient(config *Config) (*Client, error)` - Initialize transit client
- `Config() *Config` - Return configuration
- `Close() error` - Cleanup resources
- `Health(ctx context.Context) error` - Health check
- `ValidateConnection(ctx context.Context) error` - Verify mount and authentication
- `Ping(ctx context.Context) error` - Alias for Health
- `Sys() *api.Sys` - Expose system API
- `Logical() *api.Logical` - Expose logical API for advanced use

**Validation:**
- Verify transit mount exists
- Check authentication and permissions
- Validate mount accessibility

---

#### **File: `config.go`**
Configuration structure, mirroring `bao/pki/config.go`.

**Type:**
```go
type Config struct {
    Address      string         // OpenBao server URL (required)
    Token        string         // Authentication token (required)
    Namespace    string         // Namespace (optional, Enterprise)
    Mount        string         // Transit mount path (default: "transit")
    TLSConfig    *tls.Config    // TLS configuration (optional)
    HTTPClient   *http.Client   // Custom HTTP client (optional)
    Timeout      time.Duration  // Request timeout (default: 30s)
    RetryConfig  *RetryConfig   // Retry configuration (optional)
    MaxBatchSize int            // Maximum items per batch (default: 250)
}

type RetryConfig struct {
    MaxRetries int           // Maximum retry attempts (default: 3)
    BaseDelay  time.Duration // Initial delay (default: 1s)
    MaxDelay   time.Duration // Maximum delay (default: 30s)
    Multiplier float64       // Backoff multiplier (default: 2.0)
}
```

**Functions:**
- `Validate() error` - Validate configuration
- `DefaultRetryConfig() *RetryConfig` - Return default retry settings

**Defaults:**
- Mount: `"transit"`
- Timeout: `30 * time.Second`
- RetryConfig: 3 retries with exponential backoff
- MaxBatchSize: `250` (based on OpenBao's max_request_json_strings limit)

---

#### **File: `errors.go`**
Predefined errors for Transit operations.

**Errors:**
```go
var (
    // Authentication and authorization errors
    ErrUnauthorized     = errors.New("bao: authentication failed")
    ErrPermissionDenied = errors.New("bao: permission denied")

    // Connection errors
    ErrTimeout           = errors.New("bao: operation timeout")
    ErrHealthCheckFailed = errors.New("bao: health check failed")

    // Mount errors
    ErrMountNotFound = errors.New("bao: Transit mount not found")

    // Key errors
    ErrKeyNotFound        = errors.New("bao: key not found")
    ErrKeyVersionNotFound = errors.New("bao: key version not found")
    ErrKeyNotExportable   = errors.New("bao: key is not exportable")
    ErrKeyNotDeletable    = errors.New("bao: key deletion not allowed")

    // Encryption errors
    ErrInvalidCiphertext              = errors.New("bao: invalid ciphertext")
    ErrContextRequired                = errors.New("bao: context required for derived key")
    ErrConvergentEncryptionRequired   = errors.New("bao: convergent encryption not enabled")
    ErrInvalidBase64                  = errors.New("bao: invalid base64 encoding")

    // Signing errors
    ErrInvalidSignature = errors.New("bao: invalid signature")
    ErrKeyNotSigning    = errors.New("bao: key does not support signing")
)
```

**Helper Functions:**
- `IsAuthError(err error) bool` - Check if error is authentication-related
- `IsNotFoundError(err error) bool` - Check if error is not-found-related
- `IsEncryptionError(err error) bool` - Check if error is encryption-related

---

#### **File: `types.go`**
Common types and structures for Transit operations.

**Key Information:**
```go
type KeyInfo struct {
    Name                 string            // Key name
    Type                 string            // Key type (aes256-gcm96, rsa-2048, etc.)
    DeletionAllowed      bool              // Can key be deleted
    Derived              bool              // Key derivation enabled
    Exportable           bool              // Can key be exported
    AllowPlaintextBackup bool              // Allow plaintext backup
    LatestVersion        int               // Latest key version
    MinDecryptionVersion int               // Minimum version for decryption
    MinEncryptionVersion int               // Minimum version for encryption
    SupportsEncryption   bool              // Supports encryption
    SupportsDecryption   bool              // Supports decryption
    SupportsSigning      bool              // Supports signing
    SupportsDerivation   bool              // Supports key derivation
    AutoRotatePeriod     time.Duration     // Auto-rotation period
    Keys                 map[int]KeyVersion // Version information
    ConvergentEncryption bool              // Convergent encryption enabled
    ConvergentVersion    int               // Version for convergent encryption
}

type KeyVersion struct {
    CreationTime time.Time // When version was created
    PublicKey    string    // Public key (for asymmetric keys)
}
```

**Key Type Constants:**
```go
const (
    // Symmetric encryption
    KeyTypeAES128GCM96       = "aes128-gcm96"
    KeyTypeAES256GCM96       = "aes256-gcm96"
    KeyTypeChaCha20Poly1305  = "chacha20-poly1305"
    KeyTypeXChaCha20Poly1305 = "xchacha20-poly1305"

    // Asymmetric encryption
    KeyTypeRSA2048 = "rsa-2048"
    KeyTypeRSA3072 = "rsa-3072"
    KeyTypeRSA4096 = "rsa-4096"

    // Signing
    KeyTypeECDSAP256 = "ecdsa-p256"
    KeyTypeECDSAP384 = "ecdsa-p384"
    KeyTypeECDSAP521 = "ecdsa-p521"
    KeyTypeEd25519   = "ed25519"

    // HMAC (managed keys)
    KeyTypeHMAC = "hmac"
)
```

**Batch Size Limits:**
```go
const (
    // DefaultMaxBatchSize is the recommended maximum batch size
    // Based on OpenBao's max_request_json_strings limit (default 1000)
    // Assumes ~4 keys per item (plaintext, context, nonce, associated_data)
    DefaultMaxBatchSize = 250

    // AbsoluteMaxBatchSize is the absolute maximum if users configure higher limits
    AbsoluteMaxBatchSize = 1000
)
```

**Error Type:**
```go
type TransitError struct {
    Operation  string   // Operation that failed
    StatusCode int      // HTTP status code
    Errors     []string // Error messages
    Err        error    // Underlying error
}

func (e *TransitError) Error() string
func (e *TransitError) Unwrap() error
```

---

## Phase 2: Key Management Operations

### 2.1 Key Lifecycle

#### **File: `key.go`**
Complete key lifecycle management with generic type-safe clients.

**Generic Key Types:**
```go
// KeyType interface constraint for type-safe key operations
type KeyType interface {
    KeyTypeName() string
    SupportsEncryption() bool
    SupportsSigning() bool
}

// Concrete key type implementations (zero-value types for generics)
type KeyTypeAES256 struct{}
func (KeyTypeAES256) KeyTypeName() string { return KeyTypeAES256GCM96 }
func (KeyTypeAES256) SupportsEncryption() bool { return true }
func (KeyTypeAES256) SupportsSigning() bool { return false }

type KeyTypeChaCha20 struct{}
func (KeyTypeChaCha20) KeyTypeName() string { return KeyTypeChaCha20Poly1305 }
func (KeyTypeChaCha20) SupportsEncryption() bool { return true }
func (KeyTypeChaCha20) SupportsSigning() bool { return false }

type KeyTypeRSA2048 struct{}
func (KeyTypeRSA2048) KeyTypeName() string { return "rsa-2048" }
func (KeyTypeRSA2048) SupportsEncryption() bool { return true }
func (KeyTypeRSA2048) SupportsSigning() bool { return true }

type KeyTypeEd25519 struct{}
func (KeyTypeEd25519) KeyTypeName() string { return "ed25519" }
func (KeyTypeEd25519) SupportsEncryption() bool { return false }
func (KeyTypeEd25519) SupportsSigning() bool { return true }

// Similar for other key types...
```

**KeyClient[T] - Type-safe key operations:**
```go
// KeyClient provides type-safe operations for a specific key type
// Similar to bao/pki KeyClient[K] pattern
type KeyClient[T KeyType] struct {
    client  *Client
    keyName string
    keyInfo *KeyInfo
    keyType T
}

// Key operations on KeyClient
func (kc *KeyClient[T]) KeyInfo() *KeyInfo
func (kc *KeyClient[T]) KeyName() string
func (kc *KeyClient[T]) Delete(ctx context.Context) error
func (kc *KeyClient[T]) UpdateConfig(ctx context.Context, opts *UpdateKeyOptions) error
func (kc *KeyClient[T]) Rotate(ctx context.Context) error
func (kc *KeyClient[T]) Export(ctx context.Context, keyType ExportKeyType, version int) (map[int]string, error)
func (kc *KeyClient[T]) Backup(ctx context.Context) (string, error)

// Type-specific operations (only available if key supports them)
// Encryption operations - only for encryption-capable keys
func (kc *KeyClient[T]) Encrypt(ctx context.Context, plaintext []byte, opts *EncryptOptions) (*EncryptResult, error)
func (kc *KeyClient[T]) Decrypt(ctx context.Context, ciphertext string, opts *DecryptOptions) (*DecryptResult, error)

// Signing operations - only for signing-capable keys
func (kc *KeyClient[T]) Sign(ctx context.Context, input []byte, opts *SignOptions) (*SignResult, error)
func (kc *KeyClient[T]) Verify(ctx context.Context, input []byte, signature string, opts *VerifyOptions) (*VerifyResult, error)
```

**Create Keys:**
```go
type CreateKeyOptions struct {
    Derived              bool          // Enable key derivation
    Convergent           bool          // Enable convergent encryption
    Exportable           bool          // Allow key export
    AllowPlaintextBackup bool          // Allow plaintext backup
    AutoRotatePeriod     time.Duration // Auto-rotation period
}

// Generic create - returns type-safe KeyClient
func CreateKey[T KeyType](ctx context.Context, c *Client, name string, opts *CreateKeyOptions) (*KeyClient[T], error)

// Type-specific convenience methods (return type-safe clients)
func (c *Client) CreateAES256Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeAES256], error)
func (c *Client) CreateChaCha20Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeChaCha20], error)
func (c *Client) CreateRSA2048Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeRSA2048], error)
func (c *Client) CreateRSA4096Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeRSA4096], error)
func (c *Client) CreateEd25519Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeEd25519], error)
func (c *Client) CreateECDSAP256Key(ctx context.Context, name string, opts *CreateKeyOptions) (*KeyClient[KeyTypeECDSAP256], error)

// Example usage:
// keyClient, err := client.CreateAES256Key(ctx, "my-key", &CreateKeyOptions{Derived: true})
// result, err := keyClient.Encrypt(ctx, plaintext, nil) // Type-safe - knows this key supports encryption
```

**Read/List Keys:**
```go
// Get key information (type-agnostic)
func (c *Client) GetKey(ctx context.Context, name string) (*KeyInfo, error)

// Get type-safe key client
func GetKey[T KeyType](ctx context.Context, c *Client, name string) (*KeyClient[T], error)

// Type-specific getters (return type-safe clients)
func (c *Client) GetAES256Key(ctx context.Context, name string) (*KeyClient[KeyTypeAES256], error)
func (c *Client) GetChaCha20Key(ctx context.Context, name string) (*KeyClient[KeyTypeChaCha20], error)
func (c *Client) GetRSA2048Key(ctx context.Context, name string) (*KeyClient[KeyTypeRSA2048], error)
func (c *Client) GetEd25519Key(ctx context.Context, name string) (*KeyClient[KeyTypeEd25519], error)

// List all key names
func (c *Client) ListKeys(ctx context.Context) ([]string, error)

// Example usage:
// aesKey, err := client.GetAES256Key(ctx, "my-encryption-key")
// result, err := aesKey.Encrypt(ctx, data, nil) // Compile-time type safety
```

**Update Keys:**
```go
type UpdateKeyOptions struct {
    MinDecryptionVersion *int          // Minimum decryption version
    MinEncryptionVersion *int          // Minimum encryption version
    DeletionAllowed      *bool         // Allow deletion
    Exportable           *bool         // Allow export (irreversible)
    AllowPlaintextBackup *bool         // Allow plaintext backup
    AutoRotatePeriod     *time.Duration // Auto-rotation period
}

func (c *Client) UpdateKeyConfig(ctx context.Context, name string, opts *UpdateKeyOptions) error
```

**Delete/Restore Keys:**
```go
// Soft delete (can be restored)
func (c *Client) DeleteKey(ctx context.Context, name string) error

// Restore deleted key
func (c *Client) RestoreKey(ctx context.Context, name string) error
```

**Key Rotation:**
```go
// Manually rotate key
func (c *Client) RotateKey(ctx context.Context, name string) error

// Trim old versions
func (c *Client) TrimKeyVersions(ctx context.Context, name string, minVersion int) error
```

**Import/Export:**

**Key Import with Secure Wrapping (BYOK - Bring Your Own Key):**

OpenBao uses a **two-layer encryption** mechanism for secure key import:
1. Target key is wrapped with an ephemeral AES key (using KWP - Key Wrap with Padding)
2. Ephemeral AES key is encrypted with OpenBao's 4096-bit RSA public wrapping key (using RSA-OAEP)

```go
type ImportKeyOptions struct {
    Type                 string        // Key type (required: aes256-gcm96, rsa-2048, ed25519, etc.)
    HashFunction         string        // Hash for RSA-OAEP (SHA256, SHA384, SHA512, SHA1) - default: SHA256
    Derived              bool          // Enable key derivation
    Convergent           bool          // Enable convergent encryption
    Exportable           bool          // Allow export
    AllowPlaintextBackup bool          // Allow plaintext backup
    AutoRotatePeriod     time.Duration // Auto-rotation period
}

// WrappingKey represents OpenBao's RSA public wrapping key
type WrappingKey struct {
    PublicKey *rsa.PublicKey // 4096-bit RSA public key
    PEM       string         // PEM-encoded public key
}

// GetWrappingKey retrieves OpenBao's RSA public wrapping key
// This key is used to wrap keys during import
func (c *Client) GetWrappingKey(ctx context.Context) (*WrappingKey, error)

// ImportKey securely imports a key using two-layer encryption wrapping
//
// Process:
// 1. Retrieves OpenBao's RSA wrapping key
// 2. Generates ephemeral AES-256 key (32 bytes)
// 3. Wraps target key using KWP (Key Wrap with Padding) with ephemeral key
// 4. Encrypts ephemeral key using RSA-OAEP with wrapping key
// 5. Concatenates: [wrapped ephemeral key] + [wrapped target key]
// 6. Base64 encodes and sends to OpenBao
// 7. Securely zeros ephemeral key from memory
//
// Example:
//   opts := &ImportKeyOptions{
//       Type:         "aes256-gcm96",
//       HashFunction: "SHA256",
//       Exportable:   true,
//   }
//   err := client.ImportKey(ctx, "my-imported-key", keyBytes, opts)
func (c *Client) ImportKey(ctx context.Context, name string, keyData []byte, opts *ImportKeyOptions) error

// Helper functions for key wrapping (internal or exposed for advanced use)

// WrapKeyForImport wraps a key using OpenBao's two-layer encryption
// Returns base64-encoded ciphertext ready for import
func WrapKeyForImport(
    keyData []byte,
    wrappingKey *WrappingKey,
    hashFunc string,
) (string, error)

// generateEphemeralAESKey generates a cryptographically secure random AES-256 key
func generateEphemeralAESKey() ([]byte, error)

// wrapWithKWP wraps target key using Key Wrap with Padding (RFC 5649)
// Uses Google's Tink library internally
func wrapWithKWP(targetKey, ephemeralKey []byte) ([]byte, error)

// encryptWithRSAOAEP encrypts ephemeral key using RSA-OAEP
func encryptWithRSAOAEP(ephemeralKey []byte, wrappingKey *rsa.PublicKey, hashFunc string) ([]byte, error)

// secureZero overwrites memory with zeros to prevent key material leakage
// CRITICAL: Must be called after using ephemeral keys
func secureZero(data []byte)

// Export key material
type ExportKeyType string
const (
    ExportEncryptionKey = "encryption-key"
    ExportSigningKey    = "signing-key"
    ExportHMACKey       = "hmac-key"
)

func (c *Client) ExportKey(ctx context.Context, name string, keyType ExportKeyType, version int) (map[int]string, error)

// Backup/Restore
func (c *Client) BackupKey(ctx context.Context, name string) (string, error)
func (c *Client) RestoreBackup(ctx context.Context, name string, backup string) error
```

---

#### **File: `key_wrapping.go`**
Dedicated file for secure key import wrapping implementation.

**Purpose:**
Implements the two-layer encryption mechanism required by OpenBao for secure BYOK (Bring Your Own Key) imports.

**Implementation Details:**

```go
package transit

import (
    "crypto/rand"
    "crypto/rsa"
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

// Wrapping key management
type WrappingKey struct {
    PublicKey *rsa.PublicKey
    PEM       string
}

// GetWrappingKey retrieves the RSA public wrapping key from OpenBao
func (c *Client) GetWrappingKey(ctx context.Context) (*WrappingKey, error) {
    path := fmt.Sprintf("%s/wrapping_key", c.config.Mount)
    secret, err := c.client.Logical().ReadWithContext(ctx, path)
    if err != nil {
        return nil, fmt.Errorf("get wrapping key: %w", err)
    }

    publicKeyPEM := secret.Data["public_key"].(string)
    publicKey, err := parseRSAPublicKeyFromPEM(publicKeyPEM)
    if err != nil {
        return nil, fmt.Errorf("parse wrapping key: %w", err)
    }

    return &WrappingKey{
        PublicKey: publicKey,
        PEM:       publicKeyPEM,
    }, nil
}

// WrapKeyForImport performs the complete two-layer wrapping
// Uses memguard for secure ephemeral key handling
func WrapKeyForImport(
    targetKey []byte,
    wrappingKey *WrappingKey,
    hashFunc string,
) (string, error) {
    // 1. Generate ephemeral AES-256 key (locked in memory)
    ephemeralKey := memguard.NewBufferRandom(32)
    defer ephemeralKey.Destroy() // GUARANTEED zeroing, even on panic

    // 2. Wrap target key with KWP
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

// wrapWithKWP uses Google Tink's KWP implementation (RFC 5649)
func wrapWithKWP(plaintext, kek []byte) ([]byte, error) {
    kwp, err := subtle.NewKWP(kek)
    if err != nil {
        return nil, fmt.Errorf("create KWP: %w", err)
    }
    return kwp.Wrap(plaintext)
}

// encryptWithRSAOAEP encrypts using RSA-OAEP with configurable hash
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
        // Only use if required for legacy compatibility
        h = sha1.New()
    default:
        return nil, fmt.Errorf("unsupported hash function: %s", hashFunc)
    }

    return rsa.EncryptOAEP(h, rand.Reader, pubKey, plaintext, nil)
}

// secureZero overwrites sensitive data in memory
// Uses runtime.KeepAlive to prevent compiler optimization
// For cryptographic key material, use memguard instead
func secureZero(data []byte) {
    if len(data) == 0 {
        return
    }

    for i := range data {
        data[i] = 0
    }

    // Prevent compiler from optimizing away the zeroing
    runtime.KeepAlive(data)
}

// parseRSAPublicKeyFromPEM parses PEM-encoded RSA public key
func parseRSAPublicKeyFromPEM(pemData string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pemData))
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("parse public key: %w", err)
    }

    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("not an RSA public key")
    }

    return rsaPub, nil
}
```

**Security Considerations:**
1. **Ephemeral Key Lifetime**: Generated per-import, immediately destroyed after use
2. **Memory Safety**: `memguard` locks keys in memory (prevents swapping) and guarantees zeroing
3. **Hash Function Flexibility**: Supports SHA256, SHA384, SHA512, SHA1
4. **Error Handling**: Secure cleanup even on error paths (via defer)
5. **Tink Library**: Uses Google's battle-tested crypto library for KWP

**Dependencies:**
```go
// go.mod additions needed:
require (
    github.com/awnumar/memguard v0.23.1
    github.com/google/tink/go v1.7.0
)
```

---

## Phase 3: Encryption/Decryption Operations

### 3.1 Core Crypto Operations

#### **File: `encrypt.go`**
Encryption and decryption operations with automatic base64 handling.

**Types:**
```go
type EncryptOptions struct {
    Context       string // Context for key derivation (base64)
    KeyVersion    int    // Specific key version to use
    Nonce         string // Nonce for convergent encryption (base64)
    Type          string // "batch" for batch operations
    AssociatedData string // Associated authenticated data (base64)
}

type EncryptResult struct {
    Ciphertext string // Encrypted data (vault format: vault:v1:...)
    KeyVersion int    // Key version used
}

type DecryptOptions struct {
    Context        string // Context for key derivation (base64)
    Nonce          string // Nonce for convergent encryption (base64)
    AssociatedData string // Associated authenticated data (base64)
}

type DecryptResult struct {
    Plaintext  []byte // Decrypted data
    KeyVersion int    // Key version used
}
```

**Single Operations:**
```go
// Encrypt plaintext
// Automatically encodes plaintext to base64
func (c *Client) Encrypt(ctx context.Context, keyName string, plaintext []byte, opts *EncryptOptions) (*EncryptResult, error)

// Decrypt ciphertext
// Automatically decodes from base64
func (c *Client) Decrypt(ctx context.Context, keyName string, ciphertext string, opts *DecryptOptions) (*DecryptResult, error)

// Re-encrypt with latest key version
func (c *Client) ReEncrypt(ctx context.Context, keyName string, ciphertext string, opts *EncryptOptions) (*EncryptResult, error)
```

**Batch Operations:**
```go
type BatchEncryptItem struct {
    Plaintext      []byte // Data to encrypt
    Context        string // Context for derivation (base64)
    KeyVersion     int    // Specific version
    Nonce          string // Nonce (base64)
    AssociatedData string // AAD (base64)
}

type BatchEncryptResult struct {
    Ciphertext string // Encrypted data
    KeyVersion int    // Version used
    Error      error  // Item-specific error
}

type BatchDecryptItem struct {
    Ciphertext     string // Data to decrypt
    Context        string // Context for derivation (base64)
    Nonce          string // Nonce (base64)
    AssociatedData string // AAD (base64)
}

type BatchDecryptResult struct {
    Plaintext  []byte // Decrypted data
    KeyVersion int    // Version used
    Error      error  // Item-specific error
}

// Batch encrypt multiple items
func (c *Client) EncryptBatch(ctx context.Context, keyName string, items []BatchEncryptItem) ([]BatchEncryptResult, error)

// Batch decrypt multiple items
func (c *Client) DecryptBatch(ctx context.Context, keyName string, items []BatchDecryptItem) ([]BatchDecryptResult, error)

// Batch re-encrypt multiple items
func (c *Client) ReEncryptBatch(ctx context.Context, keyName string, items []BatchEncryptItem) ([]BatchEncryptResult, error)
```

**Helper Functions:**
```go
// Internal helpers for base64 encoding/decoding
func encodeBase64(data []byte) string
func decodeBase64(data string) ([]byte, error)
```

---

## Phase 4: Signing/Verification Operations

### 4.1 Digital Signatures

#### **File: `sign.go`**
Digital signature operations for RSA, ECDSA, and Ed25519 keys.

**Types:**
```go
type SignOptions struct {
    HashAlgorithm         string // sha2-256, sha2-384, sha2-512, etc.
    SignatureAlgorithm    string // pss, pkcs1v15 (for RSA)
    Context               string // Context for derived keys (base64)
    Prehashed             bool   // Input is already hashed
    MarshalingAlgorithm   string // asn1, jws (for ECDSA)
}

type SignResult struct {
    Signature  string // Digital signature
    KeyVersion int    // Key version used
}

type VerifyOptions struct {
    HashAlgorithm         string // Must match signing
    SignatureAlgorithm    string // Must match signing
    Context               string // Context for derived keys (base64)
    Prehashed             bool   // Input is already hashed
    MarshalingAlgorithm   string // Must match signing
}

type VerifyResult struct {
    Valid bool // Signature is valid
}
```

**Single Operations:**
```go
// Sign data
func (c *Client) Sign(ctx context.Context, keyName string, input []byte, opts *SignOptions) (*SignResult, error)

// Verify signature
func (c *Client) Verify(ctx context.Context, keyName string, input []byte, signature string, opts *VerifyOptions) (*VerifyResult, error)
```

**Batch Operations:**
```go
type BatchSignItem struct {
    Input                 []byte // Data to sign
    HashAlgorithm         string
    SignatureAlgorithm    string
    Context               string
    Prehashed             bool
    MarshalingAlgorithm   string
}

type BatchSignResult struct {
    Signature  string
    KeyVersion int
    Error      error
}

type BatchVerifyItem struct {
    Input                 []byte
    Signature             string
    HashAlgorithm         string
    SignatureAlgorithm    string
    Context               string
    Prehashed             bool
    MarshalingAlgorithm   string
}

type BatchVerifyResult struct {
    Valid bool
    Error error
}

func (c *Client) SignBatch(ctx context.Context, keyName string, items []BatchSignItem) ([]BatchSignResult, error)
func (c *Client) VerifyBatch(ctx context.Context, keyName string, items []BatchVerifyItem) ([]BatchVerifyResult, error)
```

---

## Phase 5: Additional Cryptographic Operations

### 5.1 HMAC Operations

#### **File: `hmac.go`**
HMAC generation and verification.

**Types:**
```go
type HMACOptions struct {
    KeyVersion int    // Specific key version
    Algorithm  string // Hash algorithm (sha2-256, sha2-512, etc.)
}

type HMACResult struct {
    HMAC       string // HMAC value
    KeyVersion int    // Key version used
}
```

**Operations:**
```go
// Generate HMAC
func (c *Client) GenerateHMAC(ctx context.Context, keyName string, input []byte, opts *HMACOptions) (*HMACResult, error)

// Verify HMAC
func (c *Client) VerifyHMAC(ctx context.Context, keyName string, input []byte, hmac string, opts *HMACOptions) (bool, error)

// Batch operations
type BatchHMACItem struct {
    Input      []byte
    KeyVersion int
    Algorithm  string
}

type BatchHMACResult struct {
    HMAC       string
    KeyVersion int
    Error      error
}

func (c *Client) GenerateHMACBatch(ctx context.Context, keyName string, items []BatchHMACItem) ([]BatchHMACResult, error)
func (c *Client) VerifyHMACBatch(ctx context.Context, keyName string, items []BatchHMACItem) ([]bool, error)
```

---

### 5.2 Hashing Operations

#### **File: `hash.go`**
Cryptographic hashing (no key required).

**Types:**
```go
type HashOptions struct {
    Algorithm string // sha2-256, sha2-512, sha3-256, etc.
    Format    string // hex, base64
}

type HashResult struct {
    Sum string // Hash digest
}
```

**Operations:**
```go
// Generic hash
func (c *Client) Hash(ctx context.Context, input []byte, opts *HashOptions) (*HashResult, error)

// Convenience methods
func (c *Client) HashSHA256(ctx context.Context, input []byte) (string, error)
func (c *Client) HashSHA512(ctx context.Context, input []byte) (string, error)
func (c *Client) HashSHA3_256(ctx context.Context, input []byte) (string, error)
```

---

### 5.3 Random Bytes Generation

#### **File: `random.go`**
Cryptographically secure random bytes.

**Types:**
```go
type RandomOptions struct {
    Format string // hex, base64
    Source string // platform, seal, all
}

type RandomResult struct {
    Data string // Random bytes in requested format
}
```

**Operations:**
```go
// Generate random bytes
func (c *Client) GenerateRandomBytes(ctx context.Context, numBytes int, opts *RandomOptions) (*RandomResult, error)

// Convenience methods
func (c *Client) GenerateRandomHex(ctx context.Context, numBytes int) (string, error)
func (c *Client) GenerateRandomBase64(ctx context.Context, numBytes int) (string, error)
```

---

### 5.4 Data Key Generation

#### **File: `datakey.go`**
Generate data encryption keys (envelope encryption pattern).

**Types:**
```go
type DataKeyOptions struct {
    KeyBits   int    // Key size in bits
    Nonce     string // Nonce for convergent encryption (base64)
    Context   string // Context for key derivation (base64)
}

type DataKeyResult struct {
    Plaintext  []byte // Plaintext data key (for immediate use)
    Ciphertext string // Encrypted data key (for storage)
    KeyVersion int    // Transit key version used
}

type WrappedDataKeyResult struct {
    Ciphertext string // Encrypted data key only
    KeyVersion int    // Transit key version used
}
```

**Operations:**
```go
// Generate plaintext + wrapped data key
func (c *Client) GenerateDataKey(ctx context.Context, keyName string, opts *DataKeyOptions) (*DataKeyResult, error)

// Generate wrapped data key only (no plaintext)
func (c *Client) GenerateWrappedDataKey(ctx context.Context, keyName string, opts *DataKeyOptions) (*WrappedDataKeyResult, error)

// Re-wrap existing data key with latest version
func (c *Client) RewrapDataKey(ctx context.Context, keyName string, ciphertext string, opts *DataKeyOptions) (*WrappedDataKeyResult, error)
```

---

## Phase 6: High-Level Abstractions & Helpers

### 6.1 Type-Safe Encryption Client

#### **File: `encryption_client.go`**
Fluent API for encryption workflows.

**Type:**
```go
type EncryptionClient struct {
    client     *Client
    keyName    string
    context    string
    keyVersion int
    nonce      string
}
```

**Operations:**
```go
// Create encryption client for a specific key
func (c *Client) NewEncryptionClient(keyName string) *EncryptionClient

// Fluent configuration
func (ec *EncryptionClient) WithContext(context string) *EncryptionClient
func (ec *EncryptionClient) WithKeyVersion(version int) *EncryptionClient
func (ec *EncryptionClient) WithNonce(nonce string) *EncryptionClient

// Operations
func (ec *EncryptionClient) Encrypt(ctx context.Context, plaintext []byte) (*EncryptResult, error)
func (ec *EncryptionClient) Decrypt(ctx context.Context, ciphertext string) (*DecryptResult, error)
func (ec *EncryptionClient) ReEncrypt(ctx context.Context, ciphertext string) (*EncryptResult, error)
```

**Example Usage:**
```go
client := transit.NewClient(config)
encClient := client.NewEncryptionClient("my-key").
    WithContext("user-123").
    WithKeyVersion(2)

ciphertext, err := encClient.Encrypt(ctx, []byte("secret data"))
plaintext, err := encClient.Decrypt(ctx, ciphertext.Ciphertext)
```

---

### 6.2 Signing Client

#### **File: `signing_client.go`**
Fluent API for signing workflows.

**Type:**
```go
type SigningClient struct {
    client             *Client
    keyName            string
    hashAlgorithm      string
    signatureAlgorithm string
    context            string
    prehashed          bool
}
```

**Operations:**
```go
// Create signing client for a specific key
func (c *Client) NewSigningClient(keyName string) *SigningClient

// Fluent configuration
func (sc *SigningClient) WithHashAlgorithm(algo string) *SigningClient
func (sc *SigningClient) WithSignatureAlgorithm(algo string) *SigningClient
func (sc *SigningClient) WithContext(context string) *SigningClient
func (sc *SigningClient) WithPrehashed(prehashed bool) *SigningClient

// Operations
func (sc *SigningClient) Sign(ctx context.Context, data []byte) (*SignResult, error)
func (sc *SigningClient) Verify(ctx context.Context, data []byte, signature string) (*VerifyResult, error)
```

**Example Usage:**
```go
client := transit.NewClient(config)
signingClient := client.NewSigningClient("my-signing-key").
    WithHashAlgorithm("sha2-256")

signature, err := signingClient.Sign(ctx, []byte("message"))
valid, err := signingClient.Verify(ctx, []byte("message"), signature.Signature)
```

---

## Phase 7: Testing & Documentation

### 7.1 Unit Tests

**Test Files:**
- `client_test.go` - Client initialization, config validation
- `config_test.go` - Configuration validation
- `key_test.go` - Key management operations (mocked)
- `encrypt_test.go` - Encryption/decryption (mocked)
- `sign_test.go` - Signing/verification (mocked)
- `hmac_test.go` - HMAC operations (mocked)
- `hash_test.go` - Hashing operations (mocked)
- `random_test.go` - Random generation (mocked)
- `datakey_test.go` - Data key generation (mocked)
- `encryption_client_test.go` - High-level API (mocked)
- `signing_client_test.go` - High-level API (mocked)

**Testing Utilities:**
- `testing_helpers_test.go` - Common test utilities
- Mock OpenBao responses
- Test data generators

---

### 7.2 Integration Tests

**Test Files:**
- `integration_test.go` - Setup/teardown with testcontainer
- `integration_helper_test.go` - Shared integration test helpers
- `key_integration_test.go` - Key lifecycle
- `encrypt_integration_test.go` - Encryption/decryption
- `sign_integration_test.go` - Signing/verification
- `hmac_integration_test.go` - HMAC operations
- `convergent_encryption_integration_test.go` - Convergent encryption
- `key_derivation_integration_test.go` - Context-based derivation
- `batch_operations_integration_test.go` - Batch encrypt/decrypt/sign
- `key_rotation_integration_test.go` - Key rotation workflows
- `import_export_integration_test.go` - BYOK workflows

**Integration Test Requirements:**
- Use existing `bao/testcontainer` package
- Enable Transit secrets engine
- Test against real OpenBao instance
- Cleanup after tests

---

### 7.3 Examples

**Directory Structure:**
```
examples/transit/
├── 01_basic_encryption/
│   └── main.go                    # Simple encrypt/decrypt
├── 02_key_rotation/
│   └── main.go                    # Key rotation workflow
├── 03_convergent_encryption/
│   └── main.go                    # Deterministic encryption
├── 04_key_derivation/
│   └── main.go                    # Multi-tenant key derivation
├── 05_signing/
│   └── main.go                    # Digital signatures
├── 06_envelope_encryption/
│   └── main.go                    # Data key generation
├── 07_batch_operations/
│   └── main.go                    # Batch encrypt/decrypt
├── 08_hmac/
│   └── main.go                    # HMAC generation/verification
├── 09_import_export/
│   └── main.go                    # BYOK workflows
├── 10_high_level_api/
│   └── main.go                    # Using EncryptionClient/SigningClient
└── README.md                      # Examples documentation
```

**Example Topics:**
1. **Basic encryption/decryption** - Simple AES-256 encrypt/decrypt workflow
2. **Key rotation** - Rotate keys and re-encrypt data seamlessly
3. **Convergent encryption** - Deterministic encryption for deduplication
4. **Key derivation** - Multi-tenant isolation with context-based keys
5. **Digital signatures** - Sign and verify with RSA, ECDSA, Ed25519
6. **Envelope encryption** - Data key generation for scalable encryption
7. **Batch operations** - High-performance bulk encrypt/decrypt/sign
8. **HMAC** - Message authentication codes
9. **BYOK (Bring Your Own Key)** - Secure key import with two-layer wrapping
10. **Key export and backup** - Export keys and create backups
11. **High-level fluent API** - Using EncryptionClient and SigningClient

**Example 9 Detail - BYOK Workflow:**
```go
// Generate your own key
myKey := make([]byte, 32) // AES-256 key
rand.Read(myKey)

// Import to OpenBao using secure wrapping
err := client.ImportKey(ctx, "my-imported-key", myKey, &transit.ImportKeyOptions{
    Type:         "aes256-gcm96",
    HashFunction: "SHA256",
    Exportable:   true,
})

// Key is now in OpenBao, ready to use
keyClient, err := client.GetAES256Key(ctx, "my-imported-key")
result, err := keyClient.Encrypt(ctx, []byte("sensitive data"), nil)
```

---

### 7.4 Documentation

**Package Documentation:**
- Comprehensive package-level godoc
- Overview of Transit secrets engine
- Usage patterns and best practices
- Security considerations

**README.md:**
```markdown
# Transit Secrets Engine

Integration with OpenBao Transit secrets engine for encryption as a service.

## Features
- Encryption/Decryption (symmetric & asymmetric)
- Digital signatures
- Key management
- HMAC and hashing
- Envelope encryption

## Quick Start
[Examples and usage]

## Security Best Practices
[Guidelines]
```

**Migration Guide:**
- Migrating from raw API calls
- Upgrading from other libraries
- Common patterns and anti-patterns

---

## Phase 8: Advanced Features

### 8.1 Caching & Performance (OPT-IN)

#### **File: `cache.go`**
**IMPORTANT:** Caching is OPTIONAL and DISABLED by default. Users must explicitly enable it.

**Features:**
- Cache key metadata to reduce API calls
- TTL-based expiration (default: 5 minutes)
- Thread-safe cache operations
- Cache invalidation on key updates
- **Disabled by default** - must opt-in

**Type:**
```go
type KeyCache struct {
    enabled bool
    cache   map[string]*cachedKeyInfo
    ttl     time.Duration
    mu      sync.RWMutex
}

type cachedKeyInfo struct {
    info      *KeyInfo
    expiresAt time.Time
}

// CacheConfig for opt-in caching
type CacheConfig struct {
    Enabled bool          // Must be true to enable (default: false)
    TTL     time.Duration // Cache TTL (default: 5 minutes)
}
```

**Operations:**
```go
// Create cache (disabled by default)
func NewKeyCache(config *CacheConfig) *KeyCache

func (kc *KeyCache) IsEnabled() bool
func (kc *KeyCache) Get(keyName string) (*KeyInfo, bool)
func (kc *KeyCache) Set(keyName string, info *KeyInfo)
func (kc *KeyCache) Invalidate(keyName string)
func (kc *KeyCache) Clear()
func (kc *KeyCache) Enable()
func (kc *KeyCache) Disable()
```

**Client Integration:**
```go
// Add cache to Config
type Config struct {
    // ... existing fields ...
    Cache *CacheConfig // Optional caching (nil = disabled)
}

// Example usage - OPT-IN:
config := &transit.Config{
    Address: "https://openbao.example.com",
    Token:   token,
    Cache: &transit.CacheConfig{
        Enabled: true,           // EXPLICITLY enable caching
        TTL:     5 * time.Minute,
    },
}

// Without cache config, caching is disabled (default behavior)
config := &transit.Config{
    Address: "https://openbao.example.com",
    Token:   token,
    // No Cache field = caching disabled
}
```

---

### 8.2 Middleware/Interceptors (DETAILED EXPLANATION)

#### **File: `middleware.go`**

**What is Middleware?**

Middleware (also called interceptors) are functions that wrap around your API calls to add cross-cutting concerns like logging, metrics, retries, and observability **without modifying your core business logic**.

Think of middleware as layers around your API calls:
```
Your Code → [Logging] → [Metrics] → [Retry] → OpenBao API
                ↓           ↓          ↓
            logs.txt    metrics.db  retry logic
```

**Why Use Middleware?**

1. **Observability** - Log all Transit operations for debugging
2. **Monitoring** - Track latency, error rates, throughput
3. **Reliability** - Automatic retries on transient failures
4. **Auditing** - Record who encrypted/decrypted what and when
5. **Rate Limiting** - Prevent overwhelming OpenBao with requests
6. **Tracing** - Distributed tracing with OpenTelemetry

**Example Use Case:**

Without middleware:
```go
// You have to manually log and track metrics everywhere
log.Printf("Encrypting data with key %s", keyName)
start := time.Now()
result, err := client.Encrypt(ctx, keyName, plaintext, nil)
duration := time.Since(start)
metrics.RecordLatency("encrypt", duration)
if err != nil {
    log.Printf("Encryption failed: %v", err)
    metrics.IncrementErrors("encrypt")
    return err
}
log.Printf("Encryption succeeded")
return result
```

With middleware:
```go
// Middleware handles logging and metrics automatically
result, err := client.Encrypt(ctx, keyName, plaintext, nil)
// That's it! Logging, metrics, retries all happen transparently
```

**Interface Design:**

```go
// Middleware interface for extensibility
type Middleware interface {
    // Called before API request is sent
    BeforeRequest(ctx context.Context, operation string, params map[string]interface{}) (context.Context, error)

    // Called after API response is received
    AfterRequest(ctx context.Context, operation string, result interface{}, err error) error
}

// MiddlewareChain executes middlewares in order
type MiddlewareChain struct {
    middlewares []Middleware
}

func (mc *MiddlewareChain) Add(m Middleware)
func (mc *MiddlewareChain) Execute(ctx context.Context, operation string, fn func(context.Context) (interface{}, error)) (interface{}, error)
```

**Built-in Middleware:**

**1. Retry Middleware (Built-in, respects Config.RetryConfig):**
```go
type RetryMiddleware struct {
    config *RetryConfig
}

// Automatically retries on 5xx errors, timeouts, network issues
// Uses exponential backoff
func NewRetryMiddleware(config *RetryConfig) *RetryMiddleware
```

**2. Logging Middleware (User-provided):**
```go
type LoggingMiddleware struct {
    logger Logger // Your custom logger interface
}

func (lm *LoggingMiddleware) BeforeRequest(ctx context.Context, operation string, params map[string]interface{}) (context.Context, error) {
    lm.logger.Info("Transit operation", "op", operation, "params", params)
    return ctx, nil
}

func (lm *LoggingMiddleware) AfterRequest(ctx context.Context, operation string, result interface{}, err error) error {
    if err != nil {
        lm.logger.Error("Transit operation failed", "op", operation, "error", err)
    } else {
        lm.logger.Info("Transit operation succeeded", "op", operation)
    }
    return nil
}

// Usage:
client.WithMiddleware(NewLoggingMiddleware(myLogger))
```

**3. Metrics Middleware (User-provided):**
```go
type MetricsMiddleware struct {
    recorder MetricsRecorder // Your metrics interface (Prometheus, StatsD, etc.)
}

func (mm *MetricsMiddleware) BeforeRequest(ctx context.Context, operation string, params map[string]interface{}) (context.Context, error) {
    // Store start time in context
    return context.WithValue(ctx, "start_time", time.Now()), nil
}

func (mm *MetricsMiddleware) AfterRequest(ctx context.Context, operation string, result interface{}, err error) error {
    start := ctx.Value("start_time").(time.Time)
    duration := time.Since(start)

    mm.recorder.RecordLatency(operation, duration)
    mm.recorder.IncrementCounter(operation + "_total")
    if err != nil {
        mm.recorder.IncrementCounter(operation + "_errors")
    }
    return nil
}

// Usage with Prometheus:
client.WithMiddleware(NewMetricsMiddleware(prometheusRegistry))
```

**4. OpenTelemetry Tracing Middleware (User-provided):**
```go
type TracingMiddleware struct {
    tracer trace.Tracer
}

func (tm *TracingMiddleware) BeforeRequest(ctx context.Context, operation string, params map[string]interface{}) (context.Context, error) {
    ctx, span := tm.tracer.Start(ctx, "transit."+operation)
    span.SetAttributes(attribute.String("operation", operation))
    return context.WithValue(ctx, "span", span), nil
}

func (tm *TracingMiddleware) AfterRequest(ctx context.Context, operation string, result interface{}, err error) error {
    span := ctx.Value("span").(trace.Span)
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, err.Error())
    }
    span.End()
    return nil
}
```

**Client Integration:**

```go
// Add middleware support to Client
type Client struct {
    config     *Config
    client     *api.Client
    middleware *MiddlewareChain
}

// Add middleware to client
func (c *Client) WithMiddleware(m Middleware) *Client {
    c.middleware.Add(m)
    return c
}

// Example usage with multiple middlewares:
client := transit.NewClient(config).
    WithMiddleware(NewLoggingMiddleware(logger)).
    WithMiddleware(NewMetricsMiddleware(metrics)).
    WithMiddleware(NewTracingMiddleware(tracer))

// All operations now go through middleware chain
result, err := client.Encrypt(ctx, keyName, plaintext, nil)
```

**Decision Summary:**
- **Built-in:** Only RetryMiddleware (respects existing RetryConfig)
- **User-provided:** Logging, Metrics, Tracing, Rate Limiting, Auditing
- **Extensible:** Simple interface for custom middleware

---

### 8.3 Integration with gopki (DEEP INTEGRATION)

#### **File: `integration.go`**
**GOAL:** Seamless, deep integration between Transit and all gopki types for production PKI workflows.

---

#### **8.3.1 Private Key Protection**

**Encrypt Certificate Private Keys:**
```go
// Encrypt private key from any gopki keypair
// Supports RSA, ECDSA, Ed25519 from gopki/keypair/algo
func EncryptPrivateKey[K keypair.KeyPair](
    ctx context.Context,
    client *Client,
    keyName string,
    kp K,
    opts *EncryptOptions,
) (string, error)

// Decrypt to specific keypair type
func DecryptToRSAKey(ctx context.Context, client *Client, keyName string, ciphertext string, opts *DecryptOptions) (*algo.RSAKeyPair, error)
func DecryptToECDSAKey(ctx context.Context, client *Client, keyName string, ciphertext string, opts *DecryptOptions) (*algo.ECDSAKeyPair, error)
func DecryptToEd25519Key(ctx context.Context, client *Client, keyName string, ciphertext string, opts *DecryptOptions) (*algo.Ed25519KeyPair, error)

// Generic decrypt with type parameter
func DecryptPrivateKey[K keypair.KeyPair](ctx context.Context, client *Client, keyName string, ciphertext string, opts *DecryptOptions) (K, error)

// Example usage:
rsaKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
ciphertext, err := transit.EncryptPrivateKey(ctx, transitClient, "master-key", rsaKey, nil)
// Store ciphertext in database, never store plaintext key!

// Later, decrypt when needed:
rsaKey, err := transit.DecryptToRSAKey(ctx, transitClient, "master-key", ciphertext, nil)
```

---

#### **8.3.2 Certificate Bundle Protection**

**Encrypt Entire Certificate Bundles:**
```go
// Encrypt certificate with private key (entire bundle)
func EncryptCertificateWithKey[K keypair.KeyPair](
    ctx context.Context,
    client *Client,
    keyName string,
    certificate *cert.Certificate,
    privateKey K,
    opts *EncryptOptions,
) (*EncryptedCertificateBundle, error)

// Decrypt certificate bundle
func DecryptCertificateBundle[K keypair.KeyPair](
    ctx context.Context,
    client *Client,
    keyName string,
    bundle *EncryptedCertificateBundle,
    opts *DecryptOptions,
) (*cert.Certificate, K, error)

type EncryptedCertificateBundle struct {
    CertificatePEM     string // Certificate in PEM (not encrypted, public data)
    EncryptedKey       string // Private key encrypted with Transit
    CAChainPEM         []string // CA chain (not encrypted, public data)
    KeyType            string // "rsa", "ecdsa", "ed25519"
    TransitKeyVersion  int    // Transit key version used
}

// Example usage - protecting certificate bundles:
cert, _ := cert.IssueSelfSignedCertificate(rsaKey, cert.Request{...})
bundle, err := transit.EncryptCertificateWithKey(ctx, transitClient, "cert-protection-key", cert, rsaKey, nil)
// Store bundle in database, private key is encrypted

// Later, retrieve and decrypt:
cert, privateKey, err := transit.DecryptCertificateBundle[*algo.RSAKeyPair](ctx, transitClient, "cert-protection-key", bundle, nil)
// Use cert and privateKey for TLS, etc.
```

---

#### **8.3.3 Transit-Backed PKI Operations**

**Issue Certificates with Transit-Protected Keys:**
```go
// Create CA with Transit-protected private key
type TransitBackedCA struct {
    transitClient *Client
    keyName       string
    caCert        *cert.Certificate
    encryptedKey  string
}

func NewTransitBackedCA(
    ctx context.Context,
    transitClient *Client,
    keyName string,
    caCert *cert.Certificate,
    encryptedKey string,
) *TransitBackedCA

// Sign certificate using Transit-protected CA key
func (tca *TransitBackedCA) SignCertificate(
    ctx context.Context,
    csr *cert.CertificateSigningRequest,
    opts *cert.SigningOptions,
) (*cert.Certificate, error)

// Rotate CA key (generate new key, re-encrypt)
func (tca *TransitBackedCA) RotateKey(ctx context.Context) error

// Example usage:
// 1. Create CA with Transit protection
caKey, _ := algo.GenerateRSAKeyPair(algo.KeySize4096)
caCert, _ := cert.IssueSelfSignedCertificate(caKey, cert.Request{...})
encryptedKey, _ := transit.EncryptPrivateKey(ctx, transitClient, "ca-key-protection", caKey, nil)

ca := transit.NewTransitBackedCA(ctx, transitClient, "ca-key-protection", caCert, encryptedKey)

// 2. Sign certificates (CA key decrypted on-demand, never stored in memory long-term)
clientCSR, _ := cert.CreateCSR(clientKey, cert.CSRRequest{...})
clientCert, err := ca.SignCertificate(ctx, clientCSR, &cert.SigningOptions{...})
```

---

#### **8.3.4 Integration with bao/pki Package**

**Seamless Transit + PKI Backend:**
```go
// Protect OpenBao PKI keys with Transit
type TransitProtectedPKIClient struct {
    pkiClient     *pki.Client
    transitClient *Client
    transitKey    string
}

// Wrap bao/pki client with Transit protection
func NewTransitProtectedPKIClient(
    pkiClient *pki.Client,
    transitClient *Client,
    transitKey string,
) *TransitProtectedPKIClient

// Generate key in PKI, export and encrypt with Transit
func (tpc *TransitProtectedPKIClient) GenerateAndProtectRSAKey[K keypair.KeyPair](
    ctx context.Context,
    opts *pki.GenerateKeyOptions,
) (*EncryptedPKIKey, error)

type EncryptedPKIKey struct {
    KeyID            string // OpenBao PKI key ID
    EncryptedKeyData string // Private key encrypted with Transit
    KeyInfo          *pki.KeyInfo
}

// Example usage - double protection (PKI + Transit):
// 1. Generate key in OpenBao PKI
pkiClient, _ := pki.NewClient(&pki.Config{...})
transitClient, _ := transit.NewClient(&transit.Config{...})

protectedClient := transit.NewTransitProtectedPKIClient(pkiClient, transitClient, "pki-key-protection")

// 2. Generate and protect key
encryptedKey, err := protectedClient.GenerateAndProtectRSAKey[*algo.RSAKeyPair](ctx, &pki.GenerateKeyOptions{
    KeyName: "root-ca-key",
    KeyBits: 4096,
})
// Key exists in PKI for operations, but exported copy is Transit-encrypted for backup
```

---

#### **8.3.5 Envelope Encryption for Certificates**

**Protect Large Certificate Databases:**
```go
// Use Transit data keys for envelope encryption of certificate stores
type CertificateStore struct {
    transitClient *Client
    masterKeyName string
    certificates  map[string]*EncryptedCertEntry
}

type EncryptedCertEntry struct {
    Certificate       *cert.Certificate // Public cert (not encrypted)
    EncryptedKey      []byte           // Private key encrypted with data key
    EncryptedDataKey  string           // Data key wrapped by Transit master key
    TransitKeyVersion int              // Transit master key version
}

func NewCertificateStore(transitClient *Client, masterKeyName string) *CertificateStore

// Store certificate with envelope encryption
func (cs *CertificateStore) StoreCertificate(
    ctx context.Context,
    id string,
    certificate *cert.Certificate,
    privateKey keypair.KeyPair,
) error {
    // 1. Generate data key for this certificate
    dataKey, _ := cs.transitClient.GenerateDataKey(ctx, cs.masterKeyName, &DataKeyOptions{KeyBits: 256})

    // 2. Encrypt private key with data key (using AES-GCM locally)
    encryptedKey, _ := encryptWithAES(privateKey.PrivateKeyToPEM(), dataKey.Plaintext)

    // 3. Store: certificate + encrypted private key + wrapped data key
    cs.certificates[id] = &EncryptedCertEntry{
        Certificate:       certificate,
        EncryptedKey:      encryptedKey,
        EncryptedDataKey:  dataKey.Ciphertext,
        TransitKeyVersion: dataKey.KeyVersion,
    }
}

// Retrieve and decrypt certificate
func (cs *CertificateStore) GetCertificate(ctx context.Context, id string) (*cert.Certificate, keypair.KeyPair, error) {
    entry := cs.certificates[id]

    // 1. Unwrap data key using Transit
    dataKeyPlaintext, _ := cs.transitClient.Decrypt(ctx, cs.masterKeyName, entry.EncryptedDataKey, nil)

    // 2. Decrypt private key with data key
    privateKeyPEM, _ := decryptWithAES(entry.EncryptedKey, dataKeyPlaintext.Plaintext)

    // 3. Parse private key
    privateKey, _ := parsePrivateKeyPEM(privateKeyPEM)

    return entry.Certificate, privateKey, nil
}

// Benefit: Can encrypt millions of certificates efficiently
// Only master key is in Transit, data keys are generated per-certificate
```

---

#### **8.3.6 Certificate Metadata Protection**

**Encrypt Sensitive Certificate Metadata:**
```go
// Encrypt sensitive fields in certificate metadata
type CertificateMetadata struct {
    SerialNumber string
    CommonName   string
    // Sensitive fields (encrypted):
    OwnerEmail    string `transit:"encrypt"`
    OwnerSSN      string `transit:"encrypt"`
    InternalNotes string `transit:"encrypt"`
}

// Encrypt struct fields marked with `transit:"encrypt"` tag
func EncryptStructFields(
    ctx context.Context,
    client *Client,
    keyName string,
    v interface{},
) error

func DecryptStructFields(
    ctx context.Context,
    client *Client,
    keyName string,
    v interface{},
) error

// Example usage:
metadata := &CertificateMetadata{
    SerialNumber:  "12:34:56",
    CommonName:    "example.com",
    OwnerEmail:    "user@example.com",
    OwnerSSN:      "123-45-6789",
    InternalNotes: "VIP customer",
}

// Encrypt sensitive fields
err := transit.EncryptStructFields(ctx, transitClient, "metadata-key", metadata)
// metadata.OwnerEmail, metadata.OwnerSSN, metadata.InternalNotes are now encrypted
// Store in database

// Decrypt when needed
err = transit.DecryptStructFields(ctx, transitClient, "metadata-key", metadata)
// Fields are decrypted back to plaintext
```

---

#### **8.3.7 Multi-Tenant Certificate Isolation**

**Key Derivation for Multi-Tenant PKI:**
```go
// Use key derivation for tenant isolation
type MultiTenantCertStore struct {
    transitClient *Client
    masterKeyName string
}

func NewMultiTenantCertStore(transitClient *Client, masterKeyName string) *MultiTenantCertStore

// Store certificate with tenant isolation
func (mtcs *MultiTenantCertStore) StoreCertificateForTenant(
    ctx context.Context,
    tenantID string,
    certificate *cert.Certificate,
    privateKey keypair.KeyPair,
) error {
    // Use tenant ID as context for key derivation
    context := base64.StdEncoding.EncodeToString([]byte(tenantID))

    // Encrypt with derived key
    encryptedKey, err := mtcs.transitClient.Encrypt(ctx, mtcs.masterKeyName, privateKeyBytes, &EncryptOptions{
        Context: context, // Derives unique key per tenant
    })

    // Store encrypted key
    // Each tenant's data encrypted with different derived key!
}

// Benefits:
// - Single master key in Transit
// - Per-tenant encryption without managing multiple keys
// - Cryptographic tenant isolation
```

---

#### **8.3.8 Helper Functions**

```go
// Convert between gopki types and Transit types seamlessly
func KeyPairToTransitKeyType(kp keypair.KeyPair) (string, error)
func TransitKeyTypeToKeyPairType(keyType string) (reflect.Type, error)

// Certificate validation with Transit signatures
func VerifyCertificateSignature(
    ctx context.Context,
    client *Client,
    signingKeyName string,
    certificate *cert.Certificate,
) error

// Certificate renewal with Transit-protected keys
func RenewCertificateWithTransit(
    ctx context.Context,
    transitClient *Client,
    keyName string,
    oldCert *cert.Certificate,
    encryptedKey string,
    opts *cert.RenewalOptions,
) (*cert.Certificate, error)
```

---

#### **Integration Summary**

**Files:**
- `integration.go` - Core integration functions
- `integration_pki.go` - bao/pki specific integrations
- `integration_store.go` - Certificate store implementations
- `integration_ca.go` - Transit-backed CA implementation

**Use Cases Covered:**
1. ✅ Encrypt/decrypt private keys from gopki keypairs
2. ✅ Protect entire certificate bundles
3. ✅ Transit-backed CA operations
4. ✅ Integration with bao/pki package
5. ✅ Envelope encryption for certificate databases
6. ✅ Metadata field-level encryption
7. ✅ Multi-tenant isolation with key derivation
8. ✅ Certificate renewal workflows
9. ✅ Type-safe conversions between gopki and Transit types

**Benefits:**
- 🔒 **Never store plaintext private keys**
- 🚀 **Seamless integration with existing gopki workflows**
- 🏢 **Enterprise-grade key management**
- 🔄 **Easy key rotation**
- 👥 **Multi-tenant support**
- 📦 **Scalable certificate storage**

---

## File Structure Summary

```
bao/transit/
├── client.go                                      # Main client with generic support
├── config.go                                      # Configuration (with opt-in cache)
├── errors.go                                      # Error definitions
├── types.go                                       # Common types & KeyType interface
│
├── key.go                                         # Key management (with KeyClient[T])
├── key_wrapping.go                                # Key import wrapping (two-layer encryption)
├── encrypt.go                                     # Encryption/decryption
├── sign.go                                        # Signing/verification
├── hmac.go                                        # HMAC operations
├── hash.go                                        # Hashing
├── random.go                                      # Random bytes
├── datakey.go                                     # Data key generation
│
├── encryption_client.go                           # High-level encryption API
├── signing_client.go                              # High-level signing API
│
├── cache.go                                       # Optional caching (OPT-IN)
├── middleware.go                                  # Middleware framework
│
├── integration.go                                 # Core gopki integration
├── integration_pki.go                             # bao/pki integration
├── integration_store.go                           # Certificate store (envelope encryption)
├── integration_ca.go                              # Transit-backed CA
├── integration_metadata.go                        # Metadata encryption
├── integration_multitenant.go                     # Multi-tenant support
│
├── client_test.go                                 # Unit tests
├── config_test.go
├── key_test.go
├── key_wrapping_test.go                           # Key wrapping tests
├── encrypt_test.go
├── sign_test.go
├── hmac_test.go
├── hash_test.go
├── random_test.go
├── datakey_test.go
├── encryption_client_test.go
├── signing_client_test.go
├── cache_test.go
├── middleware_test.go
├── integration_test.go                            # gopki integration unit tests
├── testing_helpers_test.go                        # Test utilities
│
├── integration_test.go                            # Integration test setup
├── integration_helper_test.go                     # Shared integration helpers
├── key_integration_test.go                        # Key lifecycle tests
├── encrypt_integration_test.go                    # Encryption tests
├── sign_integration_test.go                       # Signing tests
├── hmac_integration_test.go                       # HMAC tests
├── convergent_encryption_integration_test.go      # Convergent encryption
├── key_derivation_integration_test.go             # Key derivation
├── batch_operations_integration_test.go           # Batch operations
├── key_rotation_integration_test.go               # Key rotation
├── import_export_integration_test.go              # BYOK workflows
└── gopki_integration_test.go                      # gopki integration tests
```

---

## Implementation Phases Timeline

### Phase 1: Core Infrastructure (Week 1)
- ✅ `client.go` - Main client with middleware support
- ✅ `config.go` - Configuration with opt-in caching
- ✅ `errors.go` - Comprehensive error types
- ✅ `types.go` - KeyType interface and implementations
- ✅ Basic client initialization and validation
- ✅ Unit tests for all core components

### Phase 2: Generic Key Management (Week 1-2)
- ✅ `key.go` - KeyClient[T] with type-safe operations
- ✅ `key_wrapping.go` - Two-layer encryption for secure key import (KWP + RSA-OAEP)
- ✅ All KeyType implementations (AES256, ChaCha20, RSA, ECDSA, Ed25519)
- ✅ Create, Get, Update, Delete, Rotate operations
- ✅ Import/Export/Backup functionality with proper wrapping
- ✅ Secure memory handling (zeroing ephemeral keys)
- ✅ Support for multiple hash functions (SHA256, SHA384, SHA512, SHA1)
- ✅ Unit tests with mocks
- ✅ Integration tests with real OpenBao (including BYOK workflow)

### Phase 3: Encryption/Decryption (Week 2)
- ✅ `encrypt.go` - Single and batch operations
- ✅ Automatic base64 encoding/decoding
- ✅ Support for convergent encryption
- ✅ Support for key derivation (context)
- ✅ Re-encryption for key rotation
- ✅ Unit tests
- ✅ Integration tests

### Phase 4: Signing/Verification (Week 2-3)
- ✅ `sign.go` - Digital signatures (RSA, ECDSA, Ed25519)
- ✅ Multiple hash algorithms support
- ✅ Batch signing/verification
- ✅ Unit tests
- ✅ Integration tests

### Phase 5: Additional Cryptographic Operations (Week 3)
- ✅ `hmac.go` - HMAC generation and verification
- ✅ `hash.go` - Cryptographic hashing
- ✅ `random.go` - Random bytes generation
- ✅ `datakey.go` - Data key generation for envelope encryption
- ✅ Unit tests for all operations
- ✅ Integration tests

### Phase 6: High-Level Abstractions (Week 3-4)
- ✅ `encryption_client.go` - Fluent encryption API
- ✅ `signing_client.go` - Fluent signing API
- ✅ Integration with KeyClient[T] for type-safe operations
- ✅ Unit tests
- ✅ Integration tests

### Phase 7: Advanced Features - Caching & Middleware (Week 4)
- ✅ `cache.go` - Optional key metadata caching (OPT-IN)
- ✅ `middleware.go` - Middleware framework
- ✅ RetryMiddleware (built-in)
- ✅ Example logging/metrics/tracing middleware
- ✅ Unit tests
- ✅ Integration tests

### Phase 8: Deep gopki Integration (Week 4-5)
- ✅ `integration.go` - Private key encryption/decryption
- ✅ `integration_pki.go` - bao/pki integration
- ✅ `integration_store.go` - Certificate store with envelope encryption
- ✅ `integration_ca.go` - Transit-backed CA implementation
- ✅ `integration_metadata.go` - Metadata field encryption
- ✅ `integration_multitenant.go` - Multi-tenant isolation
- ✅ Full type-safe conversions between gopki and Transit
- ✅ Unit tests for all integration features
- ✅ Integration tests with both Transit and PKI

### Phase 9: Testing & Documentation (Week 5)
- ✅ Comprehensive integration tests
- ✅ Examples directory (11 examples covering all features)
- ✅ Package-level documentation
- ✅ README with quick start
- ✅ Security best practices guide
- ✅ Migration guide from raw API usage

### Phase 10: Review & Polish (Week 5-6)
- ✅ Performance optimization
- ✅ Benchmark tests for batch operations
- ✅ Security review
- ✅ Code coverage analysis (target >80%)
- ✅ Final API review
- ✅ Documentation review

---

## Design Principles

1. **Consistency with bao/pki**
   - Follow same patterns and conventions
   - Maintain similar API structure
   - Use same error handling approach

2. **Type Safety**
   - Use strong typing where possible
   - Leverage Go generics appropriately
   - Minimize type assertions

3. **Developer Experience**
   - Intuitive API design
   - Clear error messages
   - Comprehensive documentation
   - Rich examples

4. **Performance**
   - Support batch operations
   - Optional caching
   - Efficient base64 encoding/decoding

5. **Security**
   - Secure defaults
   - Clear security documentation
   - Validation of inputs
   - Proper handling of sensitive data

6. **Testing**
   - High test coverage (>80%)
   - Both unit and integration tests
   - Test against real OpenBao instance

---

## Design Decisions (CONFIRMED)

1. **✅ Generic Type Parameters**
   - **Decision:** YES - Use generics extensively like in `bao/pki`
   - Type-safe key clients with generic type parameters
   - Compile-time type safety for key types
   - Example: `KeyClient[KeyTypeAES256]`, `KeyClient[KeyTypeRSA2048]`

2. **✅ Caching Strategy**
   - **Decision:** OPT-IN - Caching is optional and disabled by default
   - Users must explicitly enable caching via `WithCache()` option
   - Default TTL: 5 minutes (configurable)

3. **✅ Middleware**
   - **Decision:** Explained in detail in Phase 8.2
   - Built-in: Retry middleware (respects RetryConfig)
   - User-provided: Logging, metrics, custom interceptors
   - Standard interface for extensibility

4. **✅ Integration with gopki**
   - **Decision:** AS DEEP AS POSSIBLE
   - First-class integration within transit package
   - Direct support for gopki types (keypair.KeyPair, cert.Certificate)
   - Seamless workflows between Transit and PKI
   - Helper utilities for common patterns

5. **✅ Batch Operation Size Limits**
   - **Decision:** Max 250 items per batch (default), configurable up to 1000
   - Based on OpenBao's `max_request_json_strings` limit (default: 1000)
   - Automatic chunking implemented for larger batches
   - Configurable via `Config.MaxBatchSize`

---

## Success Criteria

- ✅ All Transit API endpoints covered
- ✅ Comprehensive test coverage (>80%)
- ✅ Integration tests pass against OpenBao
- ✅ Complete examples for all major features
- ✅ Documentation complete with security best practices
- ✅ API consistent with `bao/pki` package
- ✅ Performance benchmarks for batch operations
- ✅ Zero security vulnerabilities in code review

---

## References

- [OpenBao Transit API Documentation](https://openbao.org/api-docs/secret/transit/)
- [Vault Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [GoPKI bao/pki Package](../pki/)
- [OpenBao Go SDK](https://github.com/openbao/openbao/tree/main/api)
- [Priority 1 Updates & Security Guide](./PRIORITY_1_UPDATES.md)

---

## Security Considerations

**⚠️ CRITICAL: Read [PRIORITY_1_UPDATES.md](./PRIORITY_1_UPDATES.md) for comprehensive security documentation**

### Quick Security Checklist

#### Key Management
- ✅ Rotate keys every 1-3 years minimum
- ✅ Use separate keys for dev/staging/prod
- ✅ Never make keys exportable unless absolutely necessary
- ✅ Document key deletion policy

#### Memory Safety
- ✅ Use **memguard** library for ephemeral cryptographic keys
- ✅ Use `secureZero()` with `runtime.KeepAlive` for other sensitive data
- ✅ Never log sensitive data (keys, plaintext, passwords)
- ✅ Use `[]byte` instead of `string` for secrets

#### Access Control
- ✅ Apply principle of least privilege
- ✅ Separate policies for encrypt/decrypt/manage operations
- ✅ Regular access audits

#### Audit Logging
- ✅ Log all key management operations (create, rotate, delete, export)
- ✅ Sample standard operations (1-10% of encrypt/decrypt)
- ✅ Use audit middleware for compliance

#### Compliance
- ✅ **FIPS**: Use AES-256, RSA-2048+, ECDSA P-256+ (avoid ChaCha20)
- ✅ **GDPR**: Implement right-to-be-forgotten workflows
- ✅ **PCI-DSS**: Annual key rotation, non-exportable keys, audit logs

#### Network Security
- ✅ TLS 1.2+ with strong cipher suites only
- ✅ Certificate validation enabled (no `InsecureSkipVerify`)
- ✅ Pin CA certificates

#### Common Vulnerabilities to Avoid
- ❌ **NEVER** reuse nonces (except for convergent encryption)
- ❌ **NEVER** use predictable contexts for derived keys
- ❌ **NEVER** ignore errors or use `_` for error handling
- ❌ **NEVER** hardcode tokens or credentials
- ❌ **NEVER** skip TLS certificate validation

### Implementation Requirements

**Before Production Deployment:**
1. Complete security checklist in PRIORITY_1_UPDATES.md (30+ items)
2. Implement audit logging middleware
3. Configure TLS with certificate pinning
4. Document key rotation schedule
5. Set up monitoring and alerting
6. Conduct security review

**Detailed Documentation:**
- **Section 2.1**: Key Management Security (rotation, deletion)
- **Section 2.2**: Access Control (policies, separation)
- **Section 2.3**: Audit Logging (what to log, middleware)
- **Section 2.4**: Compliance (FIPS, GDPR, PCI-DSS)
- **Section 2.5**: Memory Safety (memguard, secureZero)
- **Section 2.6**: Network Security (TLS, certificates)
- **Section 2.7**: Disaster Recovery (backups, replication)
- **Section 2.8**: Common Vulnerabilities (nonce reuse, timing attacks)
- **Section 2.9**: Complete Security Checklist

See [PRIORITY_1_UPDATES.md](./PRIORITY_1_UPDATES.md) for complete implementation details, code examples, and best practices.

---

## UPDATED PLAN SUMMARY

### ✅ Key Decisions Implemented:

1. **✅ Extensive Generic Usage**
   - `KeyClient[T KeyType]` for type-safe key operations
   - Generic functions for encryption/decryption with keypairs
   - Compile-time type safety throughout the API
   - Pattern consistent with `bao/pki` package

2. **✅ Opt-In Caching**
   - Caching **DISABLED by default**
   - Must explicitly set `Config.Cache.Enabled = true`
   - Clear documentation of opt-in behavior
   - TTL configurable (default 5 minutes)

3. **✅ Middleware Fully Explained**
   - Detailed explanation of what middleware is and why it's useful
   - Built-in: RetryMiddleware only
   - User-provided: Logging, Metrics, Tracing examples
   - Extensible interface for custom middleware
   - Real-world examples with Prometheus, OpenTelemetry

4. **✅ Deep gopki Integration**
   - 6 integration files covering all use cases
   - Private key encryption/decryption with type safety
   - Certificate bundle protection
   - Transit-backed CA implementation
   - bao/pki package integration
   - Envelope encryption for certificate stores
   - Metadata field-level encryption
   - Multi-tenant isolation with key derivation
   - Full type-safe conversions between gopki and Transit types

### 📊 Project Stats:

- **Total Files:** ~46 files (implementation + tests)
- **Core Files:** 18 implementation files (added `key_wrapping.go`)
- **Test Files:** 21+ test files (unit + integration)
- **Integration Files:** 6 files for gopki integration
- **Examples:** 11 comprehensive examples
- **Timeline:** 5-6 weeks
- **Target Coverage:** >80%
- **External Dependencies:** memguard (secure memory), Google Tink (KWP implementation)

### 🎯 Major Features:

1. **Type-Safe Operations** - Generic KeyClient[T] for compile-time safety
2. **All Transit APIs** - Complete coverage of Transit secrets engine
3. **Secure BYOK** - Two-layer encryption for key import (KWP + RSA-OAEP)
4. **Batch Operations** - High-performance bulk operations
5. **Middleware Support** - Extensible interceptor pattern
6. **Opt-In Caching** - Optional performance optimization
7. **Deep gopki Integration** - Seamless PKI + Transit workflows
8. **Envelope Encryption** - Scalable certificate storage
9. **Multi-Tenant Support** - Key derivation for tenant isolation
10. **Memory Safety** - memguard for ephemeral keys, secure zeroing, panic-safe cleanup

### 🚀 Ready for Implementation!

The plan is comprehensive, well-structured, and ready to execute. All design decisions have been made and documented. Next step: Begin Phase 1 implementation.
