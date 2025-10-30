// Package transit provides a Go client for OpenBao's Transit secrets engine,
// offering "Encryption as a Service" capabilities with type-safe operations.
//
// The Transit secrets engine enables applications to perform cryptographic operations
// without exposing key material. This package provides:
//   - Symmetric and asymmetric encryption/decryption
//   - Digital signatures (RSA, ECDSA, Ed25519)
//   - Key management (create, rotate, import, export)
//   - HMAC generation and verification
//   - Cryptographic hashing and random bytes generation
//   - Data key generation for envelope encryption
//   - Batch operations for high throughput
//
// Example usage:
//
//	config := &transit.Config{
//	    Address: "https://openbao.example.com",
//	    Token:   token,
//	    Mount:   "transit",
//	}
//
//	client, err := transit.NewClient(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Create a key and get a type-safe client
//	keyClient, err := client.CreateAES256Key(ctx, "my-key", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Encrypt data
//	result, err := keyClient.Encrypt(ctx, []byte("secret data"), nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
package transit

import (
	"fmt"
	"time"
)

// KeyInfo represents metadata about a Transit key.
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

// KeyVersion represents information about a specific key version.
type KeyVersion struct {
	CreationTime time.Time // When version was created
	PublicKey    string    // Public key (for asymmetric keys)
}

// Key type constants for Transit operations.
const (
	// Symmetric encryption types
	KeyTypeAES128GCM96       = "aes128-gcm96"
	KeyTypeAES256GCM96       = "aes256-gcm96"
	KeyTypeChaCha20Poly1305  = "chacha20-poly1305"
	KeyTypeXChaCha20Poly1305 = "xchacha20-poly1305"

	// Asymmetric encryption types
	KeyTypeRSA2048 = "rsa-2048"
	KeyTypeRSA3072 = "rsa-3072"
	KeyTypeRSA4096 = "rsa-4096"

	// Signing types
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
	KeyTypeECDSAP521 = "ecdsa-p521"
	KeyTypeEd25519   = "ed25519"

	// HMAC (managed keys)
	KeyTypeHMAC = "hmac"
)

// Batch size limits based on OpenBao server constraints.
const (
	// DefaultMaxBatchSize is the recommended maximum batch size.
	// Based on OpenBao's max_request_json_strings limit (default 1000).
	// Assumes ~4 keys per item (plaintext, context, nonce, associated_data).
	DefaultMaxBatchSize = 250

	// AbsoluteMaxBatchSize is the absolute maximum if users configure higher limits.
	// Should not be exceeded even if server is configured with higher limits.
	AbsoluteMaxBatchSize = 1000
)

// TransitError represents an error from a Transit operation.
type TransitError struct {
	Operation  string   // Operation that failed (e.g., "Encrypt", "CreateKey")
	StatusCode int      // HTTP status code
	Errors     []string // Error messages from OpenBao
	Err        error    // Underlying error
}

// Error implements the error interface.
func (e *TransitError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("transit %s: status %d: %v", e.Operation, e.StatusCode, e.Err)
	}
	if len(e.Errors) > 0 {
		return fmt.Sprintf("transit %s: status %d: %s", e.Operation, e.StatusCode, e.Errors[0])
	}
	return fmt.Sprintf("transit %s: status %d", e.Operation, e.StatusCode)
}

// Unwrap returns the underlying error for error wrapping.
func (e *TransitError) Unwrap() error {
	return e.Err
}

// KeyType is an interface constraint for type-safe key operations.
// All key types must implement this interface to be used with KeyClient[T].
type KeyType interface {
	KeyTypeName() string       // Returns the OpenBao key type name
	SupportsEncryption() bool  // Whether this key type supports encryption
	SupportsSigning() bool     // Whether this key type supports signing
}

// Concrete key type implementations for type-safe operations.
// These are zero-value types used as generic type parameters.

// KeyTypeAES256 represents an AES-256-GCM key with 96-bit nonce.
type KeyTypeAES256 struct{}

func (KeyTypeAES256) KeyTypeName() string      { return KeyTypeAES256GCM96 }
func (KeyTypeAES256) SupportsEncryption() bool { return true }
func (KeyTypeAES256) SupportsSigning() bool    { return false }

// KeyTypeAES128 represents an AES-128-GCM key with 96-bit nonce.
type KeyTypeAES128 struct{}

func (KeyTypeAES128) KeyTypeName() string      { return KeyTypeAES128GCM96 }
func (KeyTypeAES128) SupportsEncryption() bool { return true }
func (KeyTypeAES128) SupportsSigning() bool    { return false }

// KeyTypeChaCha20 represents a ChaCha20-Poly1305 key.
type KeyTypeChaCha20 struct{}

func (KeyTypeChaCha20) KeyTypeName() string      { return KeyTypeChaCha20Poly1305 }
func (KeyTypeChaCha20) SupportsEncryption() bool { return true }
func (KeyTypeChaCha20) SupportsSigning() bool    { return false }

// KeyTypeXChaCha20 represents an XChaCha20-Poly1305 key.
type KeyTypeXChaCha20 struct{}

func (KeyTypeXChaCha20) KeyTypeName() string      { return KeyTypeXChaCha20Poly1305 }
func (KeyTypeXChaCha20) SupportsEncryption() bool { return true }
func (KeyTypeXChaCha20) SupportsSigning() bool    { return false }

// RSA2048 represents a 2048-bit RSA key type.
type RSA2048 struct{}

func (RSA2048) KeyTypeName() string      { return "rsa-2048" }
func (RSA2048) SupportsEncryption() bool { return true }
func (RSA2048) SupportsSigning() bool    { return true }

// RSA3072 represents a 3072-bit RSA key type.
type RSA3072 struct{}

func (RSA3072) KeyTypeName() string      { return "rsa-3072" }
func (RSA3072) SupportsEncryption() bool { return true }
func (RSA3072) SupportsSigning() bool    { return true }

// RSA4096 represents a 4096-bit RSA key type.
type RSA4096 struct{}

func (RSA4096) KeyTypeName() string      { return "rsa-4096" }
func (RSA4096) SupportsEncryption() bool { return true }
func (RSA4096) SupportsSigning() bool    { return true }

// ECDSAP256 represents an ECDSA key using P-256 curve.
type ECDSAP256 struct{}

func (ECDSAP256) KeyTypeName() string      { return "ecdsa-p256" }
func (ECDSAP256) SupportsEncryption() bool { return false }
func (ECDSAP256) SupportsSigning() bool    { return true }

// ECDSAP384 represents an ECDSA key using P-384 curve.
type ECDSAP384 struct{}

func (ECDSAP384) KeyTypeName() string      { return "ecdsa-p384" }
func (ECDSAP384) SupportsEncryption() bool { return false }
func (ECDSAP384) SupportsSigning() bool    { return true }

// ECDSAP521 represents an ECDSA key using P-521 curve.
type ECDSAP521 struct{}

func (ECDSAP521) KeyTypeName() string      { return "ecdsa-p521" }
func (ECDSAP521) SupportsEncryption() bool { return false }
func (ECDSAP521) SupportsSigning() bool    { return true }

// Ed25519 represents an Ed25519 signing key type.
type Ed25519 struct{}

func (Ed25519) KeyTypeName() string      { return "ed25519" }
func (Ed25519) SupportsEncryption() bool { return false }
func (Ed25519) SupportsSigning() bool    { return true }

// HMAC represents an HMAC key type.
type HMAC struct{}

func (HMAC) KeyTypeName() string      { return "hmac" }
func (HMAC) SupportsEncryption() bool { return false }
func (HMAC) SupportsSigning() bool    { return false }
