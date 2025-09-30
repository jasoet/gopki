# encryption/ - Type-Safe Data Encryption

**Multi-algorithm encryption module with envelope encryption, CMS support, and OpenSSL compatibility.**

[![Test Coverage](https://img.shields.io/badge/Coverage-89.1%25-brightgreen.svg)](https://github.com/jasoet/gopki)

## Overview

The `encryption` module is the **most sophisticated** module in GoPKI, providing:
- **Multiple encryption algorithms** (RSA-OAEP, ECDH+AES-GCM, X25519+AES-GCM)
- **Envelope encryption** for large data and multi-recipient scenarios
- **Certificate-based encryption** with PKI integration
- **CMS (RFC 5652) format** support for interoperability
- **OpenSSL compatibility** with optional OpenSSL-compatible mode

**Test Coverage: 89.1%** (highest in GoPKI)

## 🤖 AI Agent Quick Start

### File Structure Map

```
encryption/
├── encryption.go                 - High-level API and convenience functions
│                                  Core encryption types and options
│                                  Helper functions (EncryptForCertificate, DecryptWithKeyPair)
│                                  Option builders and defaults
│
├── cms.go                        - CMS format encoding/decoding
│                                  CMS encoding (EncodeToCMS)
│                                  CMS decoding with auto-detection
│                                  Format detection and validation
│
├── asymmetric/                   - Asymmetric encryption implementations
│   ├── asymmetric.go            - **START HERE**: Core asymmetric logic
│   │                             Encryptor/Decryptor interfaces
│   │                             Algorithm dispatching and routing
│   │                             Validation and helpers, error handling
│   ├── rsa.go                   - RSA-OAEP encryption
│   │                             RSA encryptor implementation
│   │                             RSA-OAEP padding and parameters
│   ├── ecdsa.go                 - ECDH + AES-GCM encryption
│   │                             ECDH key agreement
│   │                             AES-GCM encryption with derived key, curve validation
│   ├── ed25519.go               - X25519 + AES-GCM encryption
│   │                             X25519 key derivation, AES-GCM encryption
│   │                             Public-key-only limitation handling
│   ├── helpers.go               - Shared encryption utilities
│   └── *_test.go                - Comprehensive asymmetric tests
│
├── symmetric/                    - Symmetric encryption
│   ├── symmetric.go             - AES-GCM implementation
│   │                             AES-GCM encryption/decryption
│   │                             Key derivation (for envelope)
│   │                             Nonce generation and validation
│   └── symmetric_test.go        - AES-GCM tests
│
├── envelope/                     - Envelope encryption - CRITICAL for large data
│   ├── envelope.go              - **MOST COMPLEX**: Hybrid encryption
│   │                             Envelope structure and types
│   │                             Envelope creation (DEK + KEK pattern)
│   │                             Multi-recipient support
│   │                             OpenSSL-compatible mode
│   │                             Decryption and unwrapping
│   ├── envelope_test.go         - Envelope encryption tests
│   └── cms_cycle_test.go        - **CRITICAL**: CMS cycle tests
│                                  Tests the full encrypt → encode → decode → decrypt cycle
│
└── certificate/                  - Certificate-based workflows
    ├── certificate.go           - Certificate-based encryption API
    │                             Certificate extraction and validation
    │                             High-level certificate encryption
    │                             Certificate chain handling
    └── certificate_test.go      - Certificate encryption tests
```

### Key Functions Location

| Function | File | Purpose |
|----------|------|---------|
| **`EncryptForCertificate()`** | `encryption.go` | **Primary API** - Encrypt for certificate recipient |
| **`DecryptWithKeyPair()`** | `encryption.go` | **Primary API** - Decrypt with key pair |
| `EncodeToCMS()` | `cms.go` | Encode to CMS/PKCS#7 format |
| `DecodeFromCMS()` | `cms.go` | Decode from CMS with auto-detection |
| `DecodeDataWithKey()` | `cms.go` | **Key function** - Decode and decrypt CMS data |
| **Envelope Encryption** ||
| `EncryptWithCertificate()` | `envelope/envelope.go` | Create envelope for certificate |
| `Encrypt()` (envelope) | `envelope/envelope.go` | **Core envelope** - DEK + KEK pattern |
| `Decrypt()` (envelope) | `envelope/envelope.go` | Unwrap envelope and decrypt |
| **OpenSSL Compatible Mode** ||
| `OpenSSLCompatible` option | `envelope/envelope.go` | Enable OpenSSL smime compatibility |
| OpenSSL format detection | `cms.go` | Auto-detect OpenSSL format |
| **Asymmetric Algorithms** ||
| `EncryptWithRSA()` | `asymmetric/rsa.go` | RSA-OAEP encryption (≤190 bytes) |
| `EncryptWithECDSA()` | `asymmetric/ecdsa.go` | ECDH + AES-GCM (unlimited size) |
| `EncryptWithEd25519()` | `asymmetric/ed25519.go` | X25519 + AES-GCM (unlimited size) |

### Common Modification Points

**Adding New Encryption Algorithm:**
1. Create `asymmetric/newalgo.go` following `asymmetric/rsa.go` pattern
2. Implement `Encryptor` and `Decryptor` interfaces (see `asymmetric/asymmetric.go:50-150`)
3. Add algorithm constant in `encryption.go:50-100`
4. Update algorithm dispatcher in `asymmetric/asymmetric.go:180-350`
5. Add comprehensive tests following `asymmetric/rsa_test.go` patterns
6. Update envelope support in `envelope/envelope.go:380-500`

**Adding OpenSSL Compatibility Feature:**
1. Read OpenSSL compatibility implementation in `envelope/envelope.go:520-600`
2. Review existing OpenSSL test in `compatibility/encryption/encryption_test.go:350-450`
3. Understand CMS auto-detection in `cms.go:160-180`
4. Add new OpenSSL command integration in `compatibility/helpers.go`
5. Test bidirectional compatibility (OpenSSL → GoPKI and GoPKI → OpenSSL)
6. Document in `COMPATIBILITY_REPORT.md` and `docs/OPENSSL_COMPAT.md`

**Fixing Envelope Encryption Bug:**
1. **Start with tests** - Read `envelope/cms_cycle_test.go` (lines 56-155)
2. Understand the full cycle: Encrypt → EncodeToCMS → DecodeFromCMS → Decrypt
3. Check envelope structure preservation in `envelope/envelope.go:50-150`
4. Verify DEK (Data Encryption Key) and KEK (Key Encryption Key) handling
5. Run: `task test:specific -- TestCertificateEnvelopeEncryptionWithCMSCycle`
6. Test with OpenSSL: `task test:compatibility`

**Common Bug Patterns:**
- **CMS cycle breaks structure**: Check `DecodeFromCMS` doesn't decrypt prematurely
- **Multi-recipient fails**: Verify `Recipients` array is preserved
- **OpenSSL incompatibility**: Check PKCS#7 EnvelopedData format compliance
- **Memory issues with large data**: Use envelope encryption, not direct RSA

### Type Relationships

```go
// Core encryption types (encryption.go:50-150)

// Encryption algorithm identifiers
type EncryptionAlgorithm string
const (
    AlgorithmRSAOAEP    EncryptionAlgorithm = "rsa-oaep"
    AlgorithmECDH       EncryptionAlgorithm = "ecdh-aes-gcm"
    AlgorithmX25519     EncryptionAlgorithm = "x25519-aes-gcm"
    AlgorithmEnvelope   EncryptionAlgorithm = "envelope"
)

// Primary encryption data structure
type EncryptedData struct {
    Algorithm   EncryptionAlgorithm    // Which algorithm was used
    Format      EncryptionFormat       // raw, pkcs7, cms
    Data        []byte                 // Encrypted data (or PKCS#7 EnvelopedData)
    Recipients  []*RecipientInfo       // For envelope encryption
    IV          []byte                 // Initialization vector (AES-GCM)
    Tag         []byte                 // Authentication tag (AES-GCM)
    Metadata    map[string]any         // Additional metadata
}

// Recipient information for envelope encryption
type RecipientInfo struct {
    Certificate            *x509.Certificate    // Recipient's certificate
    KeyEncryptionAlgorithm EncryptionAlgorithm  // How KEK is encrypted
    EncryptedKey           []byte               // Encrypted DEK
}

// Encryption options
type EncryptOptions struct {
    Algorithm          EncryptionAlgorithm  // Algorithm to use
    OpenSSLCompatible  bool                 // Enable OpenSSL smime compatibility
    Metadata           map[string]any       // Custom metadata
}

// Integration with keypair module:
func EncryptForCertificate(data []byte, cert *x509.Certificate, opts EncryptOptions) (*EncryptedData, error)
func DecryptWithKeyPair[T keypair.KeyPair](encData *EncryptedData, keyPair T) ([]byte, error)
```

**Critical Concepts:**

**Envelope Encryption Pattern (DEK + KEK):**
```
1. Generate random Data Encryption Key (DEK) - 32 bytes for AES-256
2. Encrypt data with DEK using AES-GCM
3. Encrypt DEK with recipient's public key (Key Encryption Key - KEK)
4. Store encrypted data + encrypted DEK + IV + Tag
5. Recipient decrypts DEK with private key, then decrypts data with DEK
```

**OpenSSL Compatible Mode:**
```go
opts := encryption.DefaultEncryptOptions()
opts.OpenSSLCompatible = true  // Create standard PKCS#7 EnvelopedData

// This format can be decrypted with:
// openssl smime -decrypt -in encrypted.p7 -inkey private.pem -out decrypted.txt

// And GoPKI can decrypt OpenSSL smime encrypted data:
// openssl smime -encrypt -aes256 -binary -in data.txt -out encrypted.p7 cert.pem
// decoded := encryption.DecodeDataWithKey(cmsData, cert, privateKey)
```

### Dependencies

**This module depends on:**
- `keypair/` - Key type constraints for encryption operations
- `cert/` - Certificate handling for certificate-based encryption
- `crypto/aes` - AES symmetric encryption
- `crypto/cipher` - Cipher modes (GCM)
- `crypto/rsa` - RSA encryption
- `crypto/ecdsa` - ECDSA key agreement
- `crypto/ed25519` - Ed25519 key derivation
- `golang.org/x/crypto/curve25519` - X25519 key agreement
- `go.mozilla.org/pkcs7` - CMS/PKCS#7 format support

**Modules that depend on THIS:**
- None (encryption is a leaf module)

**External Tool Integration:**
- OpenSSL `smime` command - For envelope encryption interoperability
- OpenSSL `enc` command - For symmetric encryption testing

### Testing Strategy

**Test Files:**
- `encryption_test.go` - High-level API tests (440 lines)
- `cms_test.go` - CMS format tests (116 lines)
- `cms_generic_test.go` - Generic CMS tests (170 lines)
- `asymmetric/asymmetric_test.go` - Core asymmetric tests (883 lines)
- `asymmetric/rsa_test.go` - RSA-specific tests (323 lines)
- `asymmetric/ecdsa_test.go` - ECDSA-specific tests (416 lines)
- `asymmetric/ed25519_test.go` - Ed25519-specific tests (457 lines)
- `asymmetric/helpers_test.go` - Utility tests (496 lines)
- `symmetric/symmetric_test.go` - AES-GCM tests (726 lines)
- `envelope/envelope_test.go` - Envelope encryption tests (659 lines)
- `envelope/cms_cycle_test.go` - **CRITICAL**: CMS cycle tests (342 lines)
- `certificate/certificate_test.go` - Certificate workflow tests (621 lines)
- `compatibility/encryption/encryption_test.go` - OpenSSL compatibility

**Running Tests:**
```bash
# All encryption module tests
go test ./encryption/...

# Specific submodules
go test ./encryption/envelope/...
go test ./encryption/asymmetric/...
go test ./encryption/symmetric/...

# Critical CMS cycle test
task test:specific -- TestCertificateEnvelopeEncryptionWithCMSCycle

# OpenSSL compatibility
task test:compatibility
cd compatibility/encryption && go test -tags=compatibility -v
```

**Test Coverage: 89.1%** (6,034 lines of tests, highest in GoPKI)

### Related Documentation

- OpenSSL compatibility: [`docs/OPENSSL_COMPAT.md`](../docs/OPENSSL_COMPAT.md)
- Encryption guide: [`docs/ENCRYPTION_GUIDE.md`](../docs/ENCRYPTION_GUIDE.md) (when created)
- Algorithm selection: [`docs/ALGORITHMS.md`](../docs/ALGORITHMS.md)
- Usage examples: [`examples/encryption/main.go`](../examples/encryption/main.go)
- Example docs: [`examples/encryption/doc.md`](../examples/encryption/doc.md)
- Compatibility report: [`COMPATIBILITY_REPORT.md`](../docs/COMPATIBILITY_REPORT.md)

---

## Features

### Encryption Algorithms

| Algorithm | Data Size Limit | Key Agreement | Speed | Use Case |
|-----------|----------------|---------------|-------|----------|
| **RSA-OAEP** | ~190 bytes (2048-bit) | ❌ | Fast | Small data, maximum compatibility |
| **ECDH + AES-GCM** | Unlimited | ✅ | Fast | Large data, modern systems |
| **X25519 + AES-GCM** | Unlimited | ✅ | Fastest | High performance, Ed25519 keys |
| **Envelope** | Unlimited | ✅ | Optimal | Large data, multi-recipient |

### Envelope Encryption

Hybrid encryption combining asymmetric and symmetric cryptography:
- Generate random DEK (Data Encryption Key) for AES-256-GCM
- Encrypt data with DEK (fast symmetric encryption)
- Encrypt DEK with recipient's public key (secure key transport)
- Support multiple recipients (each gets their own encrypted DEK)

### OpenSSL Compatibility

**OpenSSL smime Interoperability:**
- ✅ **GoPKI can decrypt OpenSSL smime encrypted data** (auto-detected)
- ✅ **OpenSSL can decrypt GoPKI encrypted data** (with `OpenSSLCompatible` mode)
- ✅ Standard PKCS#7 EnvelopedData format
- ⚠️ **RSA only** - OpenSSL smime doesn't support ECDSA/Ed25519 envelope encryption

## Installation

```bash
go get github.com/jasoet/gopki/encryption
```

## Quick Start

### Certificate-Based Encryption (Recommended)

```go
package main

import (
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Setup: Generate key pair and certificate
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
    certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{...})

    // Encrypt data for certificate recipient
    data := []byte("Confidential message")
    encrypted, _ := encryption.EncryptForCertificate(
        data,
        certificate.Certificate,
        encryption.DefaultEncryptOptions(),
    )

    // Decrypt with private key
    decrypted, _ := encryption.DecryptWithKeyPair(encrypted, keyPair)

    // decrypted == data ✅
}
```

### Envelope Encryption for Large Data

```go
package main

import (
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/encryption/envelope"
)

func main() {
    // Large data (GBs supported)
    largeData := []byte("Very large document...")

    // Encrypt with envelope (hybrid encryption)
    opts := encryption.DefaultEncryptOptions()
    encrypted, _ := envelope.EncryptWithCertificate(largeData, certificate, opts)

    // Encode to CMS format for storage/transmission
    cmsData, _ := encryption.EncodeToCMS(encrypted)

    // Later... decode and decrypt
    decoded, _ := encryption.DecodeDataWithKey(cmsData, certificate.Certificate, keyPair.PrivateKey)
    decrypted, _ := envelope.Decrypt(decoded, keyPair, encryption.DefaultDecryptOptions())

    // decrypted == largeData ✅
}
```

### OpenSSL Compatible Mode

```go
package main

import (
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/encryption/envelope"
    "os"
)

func main() {
    // Enable OpenSSL compatibility
    opts := encryption.DefaultEncryptOptions()
    opts.OpenSSLCompatible = true  // Creates standard PKCS#7 EnvelopedData

    // Encrypt with OpenSSL-compatible format
    encrypted, _ := envelope.EncryptWithCertificate(data, certificate, opts)

    // Save CMS data
    cmsData, _ := encryption.EncodeToCMS(encrypted)
    os.WriteFile("encrypted.p7", cmsData, 0644)

    // Now OpenSSL can decrypt:
    // openssl smime -decrypt -in encrypted.p7 -inkey private.pem -out decrypted.txt
}
```

### Multi-Recipient Encryption

```go
package main

import (
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/encryption/envelope"
)

func main() {
    // Multiple recipients
    recipients := []*x509.Certificate{cert1, cert2, cert3}

    // Create envelope for all recipients
    data := []byte("Shared secret")
    encrypted, _ := envelope.CreateEnvelope(data, recipients, encryption.DefaultEncryptOptions())

    // Any recipient can decrypt with their private key
    decrypted1, _ := envelope.Decrypt(encrypted, keyPair1, encryption.DefaultDecryptOptions())
    decrypted2, _ := envelope.Decrypt(encrypted, keyPair2, encryption.DefaultDecryptOptions())
    decrypted3, _ := envelope.Decrypt(encrypted, keyPair3, encryption.DefaultDecryptOptions())

    // All get the same plaintext ✅
}
```

## API Reference

### High-Level API

```go
// Primary encryption API
func EncryptForCertificate(data []byte, cert *x509.Certificate, opts EncryptOptions) (*EncryptedData, error)

// Primary decryption API
func DecryptWithKeyPair[T keypair.KeyPair](encData *EncryptedData, keyPair T) ([]byte, error)

// CMS format operations
func EncodeToCMS(data *EncryptedData) ([]byte, error)
func DecodeFromCMS[T any](cmsData []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error)
func DecodeDataWithKey[T keypair.PrivateKey](data []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error)

// Options
func DefaultEncryptOptions() EncryptOptions
func DefaultDecryptOptions() DecryptOptions
```

### Envelope Encryption API

```go
// Envelope encryption for single recipient
func envelope.EncryptWithCertificate(data []byte, cert *cert.Certificate, opts EncryptOptions) (*EncryptedData, error)

// Envelope encryption for multiple recipients
func envelope.CreateEnvelope(data []byte, certs []*x509.Certificate, opts EncryptOptions) (*EncryptedData, error)

// Decrypt envelope
func envelope.Decrypt[T keypair.KeyPair](encData *EncryptedData, keyPair T, opts DecryptOptions) ([]byte, error)
```

### Asymmetric Encryption API

```go
// RSA-OAEP encryption (≤190 bytes for RSA-2048)
func asymmetric.EncryptWithRSA(data []byte, keyPair *algo.RSAKeyPair, opts EncryptOptions) (*EncryptedData, error)
func asymmetric.DecryptWithRSA(encData *EncryptedData, keyPair *algo.RSAKeyPair, opts DecryptOptions) ([]byte, error)

// ECDH + AES-GCM encryption (unlimited size)
func asymmetric.EncryptWithECDSA(data []byte, keyPair *algo.ECDSAKeyPair, opts EncryptOptions) (*EncryptedData, error)
func asymmetric.DecryptWithECDSA(encData *EncryptedData, keyPair *algo.ECDSAKeyPair, opts DecryptOptions) ([]byte, error)

// X25519 + AES-GCM encryption (unlimited size)
func asymmetric.EncryptWithEd25519(data []byte, keyPair *algo.Ed25519KeyPair, opts EncryptOptions) (*EncryptedData, error)
func asymmetric.DecryptWithEd25519(encData *EncryptedData, keyPair *algo.Ed25519KeyPair, opts DecryptOptions) ([]byte, error)
```

### Symmetric Encryption API

```go
// AES-256-GCM encryption (internal use, exposed for advanced scenarios)
func symmetric.EncryptAESGCM(data []byte, key []byte) (*EncryptedData, error)
func symmetric.DecryptAESGCM(encData *EncryptedData, key []byte) ([]byte, error)
```

## Algorithm Selection Guide

### When to Use Each Algorithm

**RSA-OAEP:**
- ✅ Small data (≤190 bytes for 2048-bit keys)
- ✅ Maximum compatibility
- ✅ No key agreement needed
- ❌ Large data (use envelope instead)

**ECDH + AES-GCM:**
- ✅ Unlimited data size
- ✅ Modern cryptography
- ✅ Smaller keys than RSA
- ✅ Good performance
- Use for ECDSA key pairs

**X25519 + AES-GCM:**
- ✅ Unlimited data size
- ✅ Fastest performance
- ✅ Smallest keys
- ✅ Memory efficient
- Use for Ed25519 key pairs

**Envelope Encryption:**
- ✅ Large files (GBs)
- ✅ Multiple recipients
- ✅ Optimal performance
- ✅ OpenSSL compatibility
- **Recommended for most use cases**

### Decision Tree

```
Need to encrypt data?
│
├─ Data > 190 bytes?
│  └─ YES → Use Envelope Encryption
│
├─ Multiple recipients?
│  └─ YES → Use Envelope Encryption
│
├─ OpenSSL compatibility needed?
│  └─ YES → Use Envelope with OpenSSLCompatible=true
│
├─ Ed25519 keys?
│  └─ YES → Use X25519 + AES-GCM or Envelope
│
├─ ECDSA keys?
│  └─ YES → Use ECDH + AES-GCM or Envelope
│
└─ RSA keys + small data?
   └─ YES → Use RSA-OAEP or Envelope
```

**General Recommendation:** Use Envelope Encryption for all scenarios unless you have a specific reason not to.

## Security Features

### Cryptographic Security

- **AES-256-GCM**: Authenticated encryption with associated data (AEAD)
- **Strong Random**: Uses `crypto/rand.Reader` for all random generation
- **Key Derivation**: Proper key agreement protocols (ECDH, X25519)
- **Authentication Tags**: GCM provides integrity and authenticity
- **Secure Padding**: RSA-OAEP with SHA-256

### Implementation Security

- **No Key Reuse**: Fresh DEKs for every envelope encryption
- **IV/Nonce Uniqueness**: Randomly generated IVs for each encryption
- **Constant-Time Operations**: Where possible (Ed25519, GCM)
- **Type Safety**: Generic constraints prevent runtime errors
- **Memory Safety**: No raw key material exposure

### OpenSSL Compatibility Security

```go
// OpenSSL-compatible mode creates standard PKCS#7 EnvelopedData
opts.OpenSSLCompatible = true

// Security considerations:
// ✅ Uses AES-256-CBC (OpenSSL standard)
// ✅ Standard PKCS#7 padding
// ✅ RSA-OAEP or PKCS#1 v1.5 for KEK encryption
// ⚠️ RSA certificates only (OpenSSL smime limitation)
// ⚠️ No AEAD in CBC mode (integrity from envelope structure)
```

## Performance Characteristics

### Encryption Performance

| Algorithm | 1KB | 1MB | 100MB | Notes |
|-----------|-----|-----|-------|-------|
| **RSA-OAEP** | ~1ms | N/A | N/A | Size limited |
| **ECDH+AES** | ~2ms | ~15ms | ~1.5s | Key agreement + AES |
| **X25519+AES** | ~1ms | ~12ms | ~1.2s | Fastest |
| **Envelope** | ~2ms | ~15ms | ~1.5s | Optimal for large data |

### Memory Usage

- **RSA-OAEP**: Minimal overhead (~2KB)
- **ECDH/X25519**: Ephemeral key pair (~200 bytes)
- **Envelope**: DEK (32 bytes) + minimal overhead
- **Large Data**: Streaming capable (constant memory)

## Error Handling

### Common Errors

```go
// Data too large for RSA-OAEP
err := encryption.ErrDataTooLarge
// Solution: Use envelope encryption or ECDH/X25519

// Invalid certificate
err := encryption.ErrInvalidCertificate
// Solution: Verify certificate validity and key usage

// Decryption failure
err := encryption.ErrDecryptionFailed
// Solution: Check key pair matches encryption certificate

// Unsupported algorithm
err := encryption.ErrUnsupportedAlgorithm
// Solution: Check algorithm compatibility

// OpenSSL mode with non-RSA key
err := encryption.ErrOpenSSLRequiresRSA
// Solution: Use RSA certificate or disable OpenSSLCompatible mode
```

## OpenSSL Integration

### Encrypting with OpenSSL, Decrypting with GoPKI

```bash
# OpenSSL encrypts
openssl smime -encrypt -aes256 -binary -in plaintext.txt -out encrypted.p7 certificate.pem
```

```go
// GoPKI decrypts
cmsData, _ := os.ReadFile("encrypted.p7")
decoded, _ := encryption.DecodeDataWithKey(cmsData, certificate, privateKey)
plaintext := decoded.Data  // Auto-detected and decrypted!
```

### Encrypting with GoPKI, Decrypting with OpenSSL

```go
// GoPKI encrypts with OpenSSL-compatible mode
opts := encryption.DefaultEncryptOptions()
opts.OpenSSLCompatible = true

encrypted, _ := envelope.EncryptWithCertificate(data, certificate, opts)
cmsData, _ := encryption.EncodeToCMS(encrypted)
os.WriteFile("encrypted.p7", cmsData, 0644)
```

```bash
# OpenSSL decrypts
openssl smime -decrypt -in encrypted.p7 -inkey private.pem -out decrypted.txt
```

### Limitations

- **OpenSSL smime** only supports RSA certificates for envelope encryption
- ECDSA and Ed25519 envelope encryption are GoPKI-only features
- OpenSSL CBC mode vs GoPKI GCM mode (different security properties)

## Testing

### Run Tests

```bash
# All encryption tests
go test ./encryption/...

# Specific submodules
go test ./encryption/envelope/... -v
go test ./encryption/asymmetric/... -v

# Critical CMS cycle test
task test:specific -- TestCertificateEnvelopeEncryptionWithCMSCycle

# OpenSSL compatibility tests
task test:compatibility
cd compatibility/encryption && go test -tags=compatibility -v

# Specific OpenSSL test
task test:specific -- TestOpenSSLEnvelopeCompatibility
```

### Test Coverage: 89.1%

**Comprehensive Test Suite:**
- Unit tests for all algorithms
- Integration tests for workflows
- CMS format round-trip tests
- OpenSSL compatibility tests
- Edge cases and error conditions
- Performance benchmarks

## Troubleshooting

### Issue: Data too large for RSA

**Problem**: `ErrDataTooLarge` when encrypting with RSA-OAEP

**Solution**: Use envelope encryption:
```go
// Instead of:
encrypted, err := asymmetric.EncryptWithRSA(largeData, keyPair, opts)

// Use envelope:
encrypted, err := envelope.EncryptWithCertificate(largeData, certificate, opts)
```

### Issue: OpenSSL can't decrypt GoPKI data

**Problem**: OpenSSL smime fails to decrypt

**Solution**: Enable OpenSSL-compatible mode:
```go
opts := encryption.DefaultEncryptOptions()
opts.OpenSSLCompatible = true  // ← Add this
encrypted, _ := envelope.EncryptWithCertificate(data, certificate, opts)
```

### Issue: GoPKI can't decrypt OpenSSL data

**Problem**: Decryption fails with OpenSSL-encrypted data

**Solution**: Use `DecodeDataWithKey()` which auto-detects format:
```go
// This auto-detects and handles OpenSSL format
decoded, _ := encryption.DecodeDataWithKey(cmsData, certificate, privateKey)
plaintext := decoded.Data  // Already decrypted
```

### Issue: Ed25519 certificate encryption fails

**Problem**: `ErrEd25519CertificateEncryptionNotSupported`

**Solution**: Ed25519 has limitations with public-key-only encryption. Use full key pair:
```go
// Certificate-based (not supported for Ed25519)
encrypted, err := encryption.EncryptForCertificate(data, ed25519Cert, opts)
// Error: Ed25519 requires full key pair

// Key-pair based (supported)
encrypted, err := asymmetric.EncryptWithEd25519(data, ed25519KeyPair, opts)
// ✅ Works!
```

## Best Practices

1. **Use Envelope Encryption by Default**: Optimal for most scenarios
2. **Enable OpenSSL Mode When Needed**: For interoperability with OpenSSL tools
3. **Validate Certificates**: Always verify certificate validity before encryption
4. **Use Type-Safe APIs**: Prefer high-level `EncryptForCertificate()` and `DecryptWithKeyPair()`
5. **Handle Errors Properly**: Check for `ErrDataTooLarge`, `ErrInvalidCertificate`, etc.
6. **Test OpenSSL Compatibility**: Use compatibility tests for production OpenSSL integration
7. **Choose Right Algorithm**: See algorithm selection guide above

## Further Reading

- **OpenSSL Compatibility**: [`docs/OPENSSL_COMPAT.md`](../docs/OPENSSL_COMPAT.md) - Complete OpenSSL integration guide
- **Encryption Guide**: [`docs/ENCRYPTION_GUIDE.md`](../docs/ENCRYPTION_GUIDE.md) - Conceptual encryption guide
- **Algorithms**: [`docs/ALGORITHMS.md`](../docs/ALGORITHMS.md) - Algorithm selection and comparisons
- **Examples**: [`examples/encryption/main.go`](../examples/encryption/main.go) - Complete working examples
- **Example Docs**: [`examples/encryption/doc.md`](../examples/encryption/doc.md) - Detailed documentation
- **Compatibility Report**: [`COMPATIBILITY_REPORT.md`](../docs/COMPATIBILITY_REPORT.md) - Test results

## License

MIT License - see [LICENSE](../LICENSE) file

---

**Part of [GoPKI](../README.md) - Type-Safe Cryptography for Production**