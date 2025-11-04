# OpenBao Transit Secrets Engine Client

A comprehensive Go client library for the [OpenBao](https://openbao.org/) Transit Secrets Engine, providing encryption-as-a-service (EaaS), signing, and key management capabilities.

**✨ NEW: Seamless gopki Integration** - Import keypairs from gopki directly without manual format conversion!

## Features

### ✅ Core Infrastructure
- Client initialization and configuration
- Automatic connection management
- Comprehensive error handling
- Context-based operation cancellation

### 🔐 Encryption & Decryption
- **Symmetric encryption** (AES-128-GCM96, AES-256-GCM96, ChaCha20-Poly1305)
- **Batch operations** with automatic chunking (up to 1000 items)
- **Convergent encryption** for deduplication
- **Context-based encryption** for multi-tenancy
- **Key rotation** without exposing plaintext (re-encryption)
- **Envelope encryption** (data key generation)
- **AEAD support** with associated data

### ✍️ Signing & Verification
- **Digital signatures** (RSA-2048/3072/4096, ECDSA P-256/P-384/P-521, Ed25519)
- **HMAC operations** for message authentication
- **Batch signing/verification**
- **Multiple hash algorithms** (SHA2-256/384/512, SHA3-256/384/512)
- **Flexible formats** (RSA-PSS, PKCS#1v15, ECDSA ASN.1, JWS)

### 🔑 Key Management
- **Key creation** with multiple algorithms
- **Key rotation** with version tracking
- **Key import/export** (BYOK - Bring Your Own Key)
- **Backup and restore** operations
- **Key trimming** to remove old versions
- **Type-safe key operations** with Go generics

### 🎲 Cryptographic Utilities
- **Random data generation** with multiple entropy sources
- **Hash operations** for data integrity
- **Base64 and hex encoding** support

## Installation

```bash
go get github.com/jasoet/gopki/bao/transit
```

## Quick Start

### Basic Encryption/Decryption

```go
package main

import (
    "context"
    "encoding/base64"
    "fmt"
    "log"

    "github.com/jasoet/gopki/bao/transit"
)

func main() {
    // Initialize client
    client, err := transit.NewClient(&transit.Config{
        Address: "https://openbao.example.com",
        Token:   "your-token",
        Mount:   "transit", // default mount point
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Create encryption key
    keyClient, err := client.CreateAES256Key(ctx, "my-key", nil)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data
    plaintext := base64.StdEncoding.EncodeToString([]byte("Hello, World!"))
    encrypted, err := client.Encrypt(ctx, "my-key", plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted.Ciphertext)

    // Decrypt data
    decrypted, err := client.Decrypt(ctx, "my-key", encrypted.Ciphertext, nil)
    if err != nil {
        log.Fatal(err)
    }

    decoded, _ := base64.StdEncoding.DecodeString(decrypted.Plaintext)
    fmt.Printf("Decrypted: %s\n", string(decoded))
}
```

### 🚀 gopki Integration (Easy Key Import)

Import keypairs from gopki **without manual PKCS#8 conversion**:

```go
package main

import (
    "context"
    "log"

    "github.com/jasoet/gopki/bao/transit"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    client, _ := transit.NewClient(&transit.Config{
        Address: "https://openbao.example.com",
        Token:   "your-token",
    })
    defer client.Close()

    ctx := context.Background()

    // Generate RSA keypair using gopki
    rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // Import directly - NO manual conversion needed! 🎉
    err := client.ImportRSAKeyPair(ctx, "my-signing-key", rsaKeyPair, &transit.ImportKeyOptions{
        Exportable: true, // Key type auto-detected from keypair
    })
    if err != nil {
        log.Fatal(err)
    }

    // Use immediately for signing
    signature, _ := client.Sign(ctx, "my-signing-key", []byte("message"), nil)
    log.Printf("Signature: %s", signature.Signature)
}
```

**Supported gopki key types:**
- `ImportRSAKeyPair()` - Auto-detects 2048/3072/4096-bit keys
- `ImportECDSAKeyPair()` - Auto-detects P-256/P-384/P-521 curves
- `ImportEd25519KeyPair()` - Auto-detects Ed25519 keys
- `ImportAESKey()` - Auto-detects AES-128/256 keys
- `ImportFromManager()` - Polymorphic import from any Manager type

**Before gopki integration:**
```go
// Manual PKCS#8 conversion required
keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
if err != nil {
    log.Fatal(err)
}
defer secureZero(keyBytes)

err = client.ImportKey(ctx, "my-key", keyBytes, &transit.ImportKeyOptions{
    Type:         transit.KeyTypeRSA2048, // Manual type specification
    HashFunction: "SHA256",
    Exportable:   true,
})
```

**After gopki integration:**
```go
// Direct import - type auto-detected!
err := client.ImportRSAKeyPair(ctx, "my-key", rsaKeyPair, &transit.ImportKeyOptions{
    Exportable: true, // That's it! 🎉
})
```

### 🎯 Manager Support (Advanced)

Work with gopki's high-level `Manager` API for maximum flexibility:

```go
// Generate key using Manager API
manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)

// Import from Manager (auto-detects key type!)
err = client.ImportFromManager(ctx, "my-key", manager, &transit.ImportKeyOptions{
    Exportable: true,
})

// Use in Transit
signature, _ := client.Sign(ctx, "my-key", []byte("data"), nil)

// Export back to Manager
exportedManager, err := client.ExportToRSAManager(ctx, "my-key", 1)

// Use Manager's conversion features
privatePEM, publicPEM, _ := exportedManager.ToPEM()
err = exportedManager.SaveToPEM("private.pem", "public.pem")

// Validate the exported key
err = exportedManager.Validate()
```

**Manager export functions:**
- `ExportToRSAManager()` - Export and wrap in RSA Manager
- `ExportToECDSAManager()` - Export and wrap in ECDSA Manager
- `ExportToEd25519Manager()` - Export and wrap in Ed25519 Manager

**Manager benefits:**
- ✅ PEM/DER/SSH format conversion
- ✅ Key validation and comparison
- ✅ Metadata extraction (algorithm, key size, curve)
- ✅ Secure file I/O with proper permissions

### Digital Signatures

```go
// Create signing key
keyClient, err := client.CreateRSA2048Key(ctx, "sign-key", nil)
if err != nil {
    log.Fatal(err)
}

// Sign data
data := base64.StdEncoding.EncodeToString([]byte("Important document"))
signature, err := client.Sign(ctx, "sign-key", data, nil)
if err != nil {
    log.Fatal(err)
}

// Verify signature
verified, err := client.Verify(ctx, "sign-key", data, signature.Signature, nil)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Signature valid: %v\n", verified.Valid)
```

### Batch Operations

```go
// Batch encryption
items := []transit.BatchEncryptItem{
    {Plaintext: base64.StdEncoding.EncodeToString([]byte("message 1"))},
    {Plaintext: base64.StdEncoding.EncodeToString([]byte("message 2"))},
    {Plaintext: base64.StdEncoding.EncodeToString([]byte("message 3"))},
}

result, err := client.EncryptBatch(ctx, "my-key", items)
if err != nil {
    log.Fatal(err)
}

for i, item := range result.Results {
    if result.Errors[i] == nil {
        fmt.Printf("Item %d encrypted: %s\n", i, item.Ciphertext)
    }
}
```

## Key Management

### Creating Keys

```go
// AES-256-GCM96 (symmetric)
aesKey, err := client.CreateAES256Key(ctx, "aes-key", &transit.CreateKeyOptions{
    Exportable: true,
    Derived:    false,
})

// RSA-2048 (asymmetric)
rsaKey, err := client.CreateRSA2048Key(ctx, "rsa-key", nil)

// ECDSA P-256
ecdsaKey, err := client.CreateECDSAP256Key(ctx, "ecdsa-key", nil)

// Ed25519
ed25519Key, err := client.CreateEd25519Key(ctx, "ed-key", nil)

// ChaCha20-Poly1305
chachaKey, err := client.CreateChaCha20Key(ctx, "chacha-key", nil)
```

### Key Rotation

```go
// Rotate to a new version
err = keyClient.Rotate(ctx)

// Re-encrypt with new version
newCiphertext, err := client.ReEncrypt(ctx, "my-key", oldCiphertext, nil)
```

### Key Import/Export (BYOK)

```go
// Generate your own key material
keyMaterial := make([]byte, 32) // 256 bits for AES-256
rand.Read(keyMaterial)

// Import key
err = client.ImportKey(ctx, "imported-key", keyMaterial, &transit.ImportKeyOptions{
    Type:       transit.KeyTypeAES256GCM96,
    Exportable: true,
})

// Export key
exported, err := client.ExportKey(ctx, "my-key", transit.ExportEncryptionKey, 0)
for version, key := range exported {
    fmt.Printf("Version %d: %s\n", version, key)
}
```

### Backup and Restore

```go
// Backup key
backup, err := client.BackupKey(ctx, "my-key")

// Restore to different name
err = client.RestoreBackup(ctx, "restored-key", backup)
```

## Advanced Features

### Convergent Encryption

For deduplication scenarios:

```go
keyClient, err := client.CreateAES256Key(ctx, "dedup-key", &transit.CreateKeyOptions{
    ConvergentEncryption: true,
    Derived:              true,
})

// Same data + context + nonce = same ciphertext
encrypted, err := client.Encrypt(ctx, "dedup-key", data, &transit.EncryptOptions{
    Context: base64.StdEncoding.EncodeToString([]byte("tenant-1")),
    Nonce:   base64.StdEncoding.EncodeToString(nonce),
})
```

### Context-Based Encryption

For multi-tenant applications:

```go
// Encrypt for tenant 1
tenant1Context := base64.StdEncoding.EncodeToString([]byte("tenant-1"))
encrypted1, err := client.Encrypt(ctx, "derived-key", data, &transit.EncryptOptions{
    Context: tenant1Context,
})

// Encrypt for tenant 2
tenant2Context := base64.StdEncoding.EncodeToString([]byte("tenant-2"))
encrypted2, err := client.Encrypt(ctx, "derived-key", data, &transit.EncryptOptions{
    Context: tenant2Context,
})
```

### Envelope Encryption

For hybrid encryption patterns:

```go
// Generate data encryption key (DEK)
dek, err := client.GenerateDataKey(ctx, "master-key", nil)

// Use DEK.Plaintext for local encryption
// Store DEK.Ciphertext with encrypted data

// Later: decrypt DEK to recover plaintext
decrypted, err := client.Decrypt(ctx, "master-key", dek.Ciphertext, nil)
```

### HMAC Operations

```go
// Generate HMAC
hmac, err := client.HMAC(ctx, "my-key", data, &transit.HMACOptions{
    Algorithm: transit.HashSHA2_256,
})

// Verify HMAC
verified, err := client.VerifyHMAC(ctx, "my-key", data, hmac.HMAC, nil)
```

### Random Data Generation

```go
// Generate 32 random bytes (base64-encoded)
random, err := client.GenerateRandomBytes(ctx, 32)

// Generate 16 random bytes (hex-encoded)
randomHex, err := client.GenerateRandomHex(ctx, 16)

// With specific entropy source
random, err := client.GenerateRandom(ctx, 32, &transit.RandomOptions{
    Source: transit.RandomSourceAll, // platform + seal
    Format: transit.RandomFormatBase64,
})
```

### Hash Operations

```go
// Hash data
data := base64.StdEncoding.EncodeToString([]byte("data to hash"))
hash, err := client.Hash(ctx, data, &transit.HashOptions{
    Algorithm: transit.HashSHA2_256,
    Format:    "hex",
})
```

## Configuration Options

### Client Configuration

```go
config := &transit.Config{
    Address:  "https://openbao.example.com",
    Token:    "your-token",
    Mount:    "transit",           // default: "transit"
    Timeout:  30 * time.Second,    // default: 60s
    MaxBatchSize: 500,             // default: 250, max: 1000
}

client, err := transit.NewClient(config)
```

### Key Creation Options

```go
options := &transit.CreateKeyOptions{
    // Allow key to be exported
    Exportable: true,

    // Enable context-based key derivation
    Derived: true,

    // Enable convergent encryption
    ConvergentEncryption: true,

    // Allow plaintext backup
    AllowPlaintextBackup: true,

    // Specific key type (optional)
    Type: transit.KeyTypeAES256GCM96,
}
```

## Supported Key Types

### Symmetric (Encryption)
- `aes128-gcm96` - AES-128-GCM with 96-bit nonce
- `aes256-gcm96` - AES-256-GCM with 96-bit nonce (recommended)
- `chacha20-poly1305` - ChaCha20-Poly1305

### Asymmetric (Signing/Encryption)
- `rsa-2048` - RSA with 2048-bit key
- `rsa-3072` - RSA with 3072-bit key
- `rsa-4096` - RSA with 4096-bit key
- `ecdsa-p256` - ECDSA using curve P-256
- `ecdsa-p384` - ECDSA using curve P-384
- `ecdsa-p521` - ECDSA using curve P-521
- `ed25519` - Ed25519 signature algorithm

### Key Derivation
- `hmac` - HMAC for key derivation and message authentication

## Error Handling

The library provides typed errors for better error handling:

```go
result, err := client.Encrypt(ctx, "my-key", plaintext, nil)
if err != nil {
    var transitErr *transit.TransitError
    if errors.As(err, &transitErr) {
        fmt.Printf("Transit error: %s (status: %d)\n",
            transitErr.Message, transitErr.StatusCode)
    }
    return err
}
```

## Thread Safety

All operations are thread-safe. The client can be safely used concurrently from multiple goroutines.

## Testing

Run unit tests:
```bash
go test ./...
```

Run integration tests (requires Docker):
```bash
go test -tags=integration ./...
```

## Performance

### Batch Operations
- Automatic chunking for operations exceeding server limits
- Default batch size: 250 items
- Maximum batch size: 1000 items (configurable)

### Connection Pooling
- Automatic HTTP connection pooling
- Configurable timeout (default: 60s)
- Graceful client shutdown with `Close()`

## Best Practices

1. **Always use base64 encoding** for plaintext and ciphertext
2. **Close clients** when done: `defer client.Close()`
3. **Use context** for operation cancellation and timeouts
4. **Enable key rotation** for long-lived keys
5. **Use batch operations** for multiple items to reduce network overhead
6. **Use envelope encryption** for large data
7. **Enable convergent encryption** only when deduplication is required
8. **Use derived keys** for multi-tenant scenarios

## Benchmarks

Run benchmarks:
```bash
go test -bench=. -benchmem
```

## Examples

See the `examples/` directory for complete working examples:
- `simple_encryption/` - Basic encryption and decryption
- `batch_operations/` - Batch processing
- `key_rotation/` - Key lifecycle management
- `signing/` - Digital signatures
- `envelope_encryption/` - Hybrid encryption pattern

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`go test ./...`)
- Integration tests pass (`go test -tags=integration ./...`)
- Code is formatted (`go fmt ./...`)
- Documentation is updated

## License

See the main repository LICENSE file.

## References

- [OpenBao Documentation](https://openbao.org/docs/)
- [OpenBao Transit Secrets Engine API](https://openbao.org/api-docs/secret/transit/)
- [Go Documentation](https://pkg.go.dev/github.com/jasoet/gopki/bao/transit)

## Support

For issues and questions:
- GitHub Issues: https://github.com/jasoet/gopki/issues
- OpenBao Community: https://github.com/openbao/openbao/discussions
