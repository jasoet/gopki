# Encryption Module Documentation

Complete documentation for the GoPKI Encryption module, demonstrating type-safe data encryption with multi-algorithm support and CMS format compliance.

## Table of Contents
- [Overview](#overview)
- [Core Features](#core-features)
- [Encryption Methods](#encryption-methods)
- [Supported Algorithms](#supported-algorithms)
- [CMS Format Support](#cms-format-support)
- [Security & Best Practices](#security--best-practices)
- [Integration Examples](#integration-examples)

## Overview

The Encryption module provides comprehensive data encryption and decryption capabilities using type-safe APIs with automatic algorithm selection based on key types. It supports direct encryption for small data, envelope encryption for large data, and industry-standard CMS (RFC 5652) format for enterprise compatibility.

### Key Design Principles
- **Type Safety**: Compile-time type checking through Go generics from keypair module
- **Algorithm Agnostic**: Automatic algorithm selection based on key type
- **Standards Compliance**: RFC 5652 CMS format support for enterprise interoperability
- **Performance Optimized**: Automatic method selection (direct vs. envelope encryption)
- **Certificate Integration**: Seamless PKI workflows with certificate-based encryption

## Core Features

### 1. Multi-Algorithm Encryption
```go
// RSA-OAEP encryption (direct for small data)
rsaManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
encrypted, err := asymmetric.Encrypt(data, rsaManager.KeyPair(), encryption.DefaultEncryptOptions())

// ECDSA + ECDH encryption (key agreement + AES-GCM)
ecdsaManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
encrypted, err := envelope.Encrypt(data, ecdsaManager.KeyPair(), encryption.DefaultEncryptOptions())

// Ed25519 + X25519 encryption (modern high-performance)
ed25519Manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair](algo.Ed25519Config{})
encrypted, err := envelope.Encrypt(data, ed25519Manager.KeyPair(), encryption.DefaultEncryptOptions())
```

### 2. Envelope Encryption for Large Data
```go
// Automatic envelope encryption for large data (hybrid encryption)
opts := encryption.DefaultEncryptOptions()
opts.Format = encryption.FormatCMS

largeData := make([]byte, 1024*100) // 100KB data
encrypted, err := envelope.Encrypt(largeData, keyPair, opts)
// Uses AES-GCM for data + RSA/ECDH for key encryption
```

### 3. Certificate-based Encryption
```go
// PKI certificate-based document encryption
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, certRequest)
encrypted, err := certenc.EncryptDocument(document, certificate, encryption.DefaultEncryptOptions())

// Decrypt using private key
decrypted, err := certenc.DecryptDocument(encrypted, keyPair, encryption.DefaultDecryptOptions())
```

### 4. CMS Format Operations
```go
// Encode to CMS format (RFC 5652)
cmsData, err := encryption.EncodeData(encrypted)

// Decode from CMS format with type-safe API
decodedData, err := encryption.DecodeDataWithKey(cmsData, certificate, privateKey)
```

## Encryption Methods

### Method Selection Matrix

| Data Size | RSA Key | ECDSA Key | Ed25519 Key | Method Used |
|-----------|---------|-----------|-------------|-------------|
| **≤190 bytes** | Direct RSA-OAEP | Envelope (ECDH+AES) | Envelope (X25519+AES) | Automatic |
| **>190 bytes** | Envelope (RSA+AES) | Envelope (ECDH+AES) | Envelope (X25519+AES) | Automatic |
| **Any size** | Envelope preferred | Envelope only | Envelope only | Manual |

### Direct Encryption
- **Use Case**: Small data that fits within key constraints
- **RSA Limit**: ~190 bytes for 2048-bit keys, ~318 bytes for 3072-bit keys
- **Performance**: Single cryptographic operation
- **Security**: Full asymmetric encryption strength

### Envelope Encryption (Hybrid)
- **Use Case**: Any data size, especially large data
- **Method**: AES-GCM for data + asymmetric encryption for AES key
- **Performance**: Optimal for large data sets
- **Security**: Combines symmetric and asymmetric encryption benefits

## Supported Algorithms

### RSA (Rivest-Shamir-Adleman)
- **Key Sizes**: 2048, 3072, 4096 bits (minimum 2048 enforced)
- **Encryption Method**: RSA-OAEP with SHA-256/SHA-384/SHA-512
- **Direct Limit**: ~190 bytes (2048-bit), ~318 bytes (3072-bit)
- **Use Cases**: Maximum compatibility, enterprise PKI environments

```go
// RSA encryption examples
rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
keyPair := rsaManager.KeyPair()

// Small data - direct encryption
smallData := []byte("Short confidential message")
encrypted, err := asymmetric.Encrypt(smallData, keyPair, encryption.DefaultEncryptOptions())

// Large data - envelope encryption
largeData := make([]byte, 10240) // 10KB
encrypted, err = envelope.Encrypt(largeData, keyPair, encryption.DefaultEncryptOptions())
```

### ECDSA + ECDH (Elliptic Curve)
- **Curves**: P-256, P-384, P-521
- **Key Agreement**: ECDH for shared secret generation
- **Symmetric Cipher**: AES-GCM with 256-bit keys
- **Use Cases**: Modern PKI, efficient encryption, smaller key sizes

```go
// ECDSA encryption examples
ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
keyPair := ecdsaManager.KeyPair()

// Always uses envelope encryption (ECDH + AES-GCM)
data := []byte("ECDSA message using ECDH key agreement")
encrypted, err := envelope.Encrypt(data, keyPair, encryption.DefaultEncryptOptions())
```

### Ed25519 + X25519 (Modern Elliptic Curve)
- **Key Size**: Fixed 256-bit keys
- **Key Agreement**: X25519 (Curve25519 for ECDH)
- **Symmetric Cipher**: AES-GCM with 256-bit keys
- **Use Cases**: High performance, modern applications, maximum security

```go
// Ed25519 encryption examples
ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair](algo.Ed25519Config{})
keyPair := ed25519Manager.KeyPair()

// Always uses envelope encryption (X25519 + AES-GCM)
data := []byte("Modern Ed25519 encryption with X25519 key agreement")
encrypted, err := envelope.Encrypt(data, keyPair, encryption.DefaultEncryptOptions())
```

## CMS Format Support

### CMS (Cryptographic Message Syntax) - RFC 5652

The encryption module provides full support for CMS format, the industry standard for cryptographic message syntax.

#### CMS Features
- **Standards Compliance**: Full RFC 5652 implementation
- **Interoperability**: Compatible with OpenSSL, Microsoft CryptoAPI, Java
- **Algorithm Agility**: Support for multiple encryption algorithms
- **Extensible**: Support for custom attributes and metadata

#### CMS Operations
```go
// Create encrypted data
encrypted, err := asymmetric.Encrypt(data, keyPair, encryption.DefaultEncryptOptions())

// Encode to CMS format
cmsData, err := encryption.EncodeData(encrypted)

// Decode from CMS format (type-safe)
decodedData, err := encryption.DecodeDataWithKey(cmsData, certificate, privateKey)

// Alternative generic decode (requires type parameter)
decodedData, err := encryption.DecodeFromCMS[*rsa.PrivateKey](cmsData, certificate, privateKey)
```

#### CMS Structure
```
CMS EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
}
```

## Security & Best Practices

### Algorithm Selection Guidelines

| Use Case | Recommended Algorithm | Key Size | Method |
|----------|----------------------|----------|--------|
| **New Applications** | Ed25519 + X25519 | 256-bit (fixed) | Envelope |
| **Enterprise PKI** | RSA 3072+ | 3072+ bits | Envelope |
| **Modern Standards** | ECDSA P-256+ | P-256+ | Envelope |
| **Legacy Compatibility** | RSA 2048+ | 2048+ bits | Direct/Envelope |
| **High Performance** | Ed25519 + X25519 | 256-bit (fixed) | Envelope |

### Encryption Method Selection
```go
// Automatic method selection based on data size and key type
func selectEncryptionMethod(dataSize int, keyType string) string {
    switch keyType {
    case "RSA":
        if dataSize <= getDirectEncryptionLimit(keyType) {
            return "Direct RSA-OAEP"
        }
        return "Envelope (RSA + AES-GCM)"
    case "ECDSA", "Ed25519":
        return "Envelope (ECDH/X25519 + AES-GCM)"
    }
}
```

### Security Considerations
- **Key Size**: Use minimum recommended key sizes for each algorithm
- **Random Numbers**: All encryption uses cryptographically secure random number generation
- **Forward Secrecy**: Envelope encryption provides forward secrecy through ephemeral keys
- **Authenticated Encryption**: AES-GCM provides both confidentiality and authenticity
- **Side-Channel Resistance**: Constant-time operations where possible

### Performance Optimization
```go
// Performance characteristics (relative, 1KB data)
Performance Rankings:
1. Ed25519 + X25519 + AES-GCM    ~1.0x (fastest)
2. ECDSA P-256 + ECDH + AES-GCM  ~1.2x
3. ECDSA P-384 + ECDH + AES-GCM  ~1.5x
4. RSA-2048 + AES-GCM            ~3.0x
5. RSA-3072 + AES-GCM            ~6.0x
6. RSA-4096 + AES-GCM            ~12.0x (slowest)
```

## Integration Examples

### Certificate Module Integration
```go
// Generate key pair for encryption
keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
keyPair := keyManager.KeyPair()

// Create certificate for recipient
certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "Document Recipient"},
    ValidFor: 365 * 24 * time.Hour,
})

// Encrypt document for certificate holder
document := []byte("Confidential business document")
encrypted, err := certenc.EncryptDocument(document, certificate, encryption.DefaultEncryptOptions())

// Decrypt using private key
decrypted, err := certenc.DecryptDocument(encrypted, keyPair, encryption.DefaultDecryptOptions())
```

### Multi-Recipient Encryption
```go
// Create multiple recipients with different algorithms
recipients := []struct {
    name    string
    keyPair interface{}
    cert    *cert.Certificate
}{
    {"Alice", rsaKeyPair, rsaCert},       // RSA-2048
    {"Bob", ecdsaKeyPair, ecdsaCert},     // ECDSA P-256
    {"Charlie", ed25519KeyPair, ed25519Cert}, // Ed25519
}

// Encrypt for each recipient separately
message := []byte("Multi-recipient confidential message")
for _, recipient := range recipients {
    encrypted, err := envelope.Encrypt(message, recipient.keyPair, encryption.DefaultEncryptOptions())
    // Each recipient gets their own encrypted copy
    saveForRecipient(encrypted, recipient.name)
}
```

### File Encryption Workflow
```go
// File encryption with CMS format
fileData, err := os.ReadFile("confidential.pdf")
if err != nil {
    log.Fatal(err)
}

// Encrypt file data
opts := encryption.DefaultEncryptOptions()
opts.Format = encryption.FormatCMS
encrypted, err := envelope.Encrypt(fileData, keyPair, opts)

// Save encrypted file in CMS format
cmsData, err := encryption.EncodeData(encrypted)
err = os.WriteFile("confidential.pdf.cms", cmsData, 0644)

// Later: decrypt the file
decodedData, err := encryption.DecodeDataWithKey(cmsData, certificate, privateKey)
decrypted, err := envelope.Decrypt(decodedData, keyPair, encryption.DefaultDecryptOptions())
err = os.WriteFile("decrypted.pdf", decrypted, 0644)
```

### Performance Testing Integration
```go
// Benchmark different encryption methods
algorithms := []struct {
    name    string
    keyPair interface{}
}{
    {"RSA-2048", rsaKeyPair},
    {"ECDSA-P256", ecdsaKeyPair},
    {"Ed25519", ed25519KeyPair},
}

testData := make([]byte, 100*1024) // 100KB test data

for _, alg := range algorithms {
    // Measure encryption performance
    startTime := time.Now()
    encrypted, err := envelope.Encrypt(testData, alg.keyPair, encryption.DefaultEncryptOptions())
    encryptTime := time.Since(startTime)

    // Measure decryption performance
    startTime = time.Now()
    decrypted, err := envelope.Decrypt(encrypted, alg.keyPair, encryption.DefaultDecryptOptions())
    decryptTime := time.Since(startTime)

    fmt.Printf("%-12s Encrypt: %-8v Decrypt: %-8v Size: %d bytes\n",
        alg.name, encryptTime, decryptTime, len(encrypted.Data))
}
```

## Error Handling

### Common Error Patterns
```go
// Encryption with proper error handling
encrypted, err := asymmetric.Encrypt(data, keyPair, opts)
if err != nil {
    if errors.Is(err, encryption.ErrDataTooLarge) {
        // Try envelope encryption for large data
        encrypted, err = envelope.Encrypt(data, keyPair, opts)
    }
    if errors.Is(err, encryption.ErrUnsupportedAlgorithm) {
        return fmt.Errorf("algorithm not supported: %w", err)
    }
    return fmt.Errorf("encryption failed: %w", err)
}

// Decryption with error handling
decrypted, err := asymmetric.Decrypt(encrypted, keyPair, decryptOpts)
if err != nil {
    if errors.Is(err, encryption.ErrDecryptionFailed) {
        return fmt.Errorf("decryption failed - wrong key?: %w", err)
    }
    if errors.Is(err, encryption.ErrInvalidFormat) {
        return fmt.Errorf("invalid encrypted data format: %w", err)
    }
    return fmt.Errorf("decryption error: %w", err)
}
```

### Error Types
- `encryption.ErrDataTooLarge`: Data exceeds direct encryption limits
- `encryption.ErrUnsupportedAlgorithm`: Algorithm not supported
- `encryption.ErrDecryptionFailed`: Cryptographic decryption failure
- `encryption.ErrInvalidFormat`: Malformed encrypted data
- `encryption.ErrMissingPrivateKey`: Private key required but not provided
- `encryption.ErrInvalidCertificate`: Certificate validation failed
- `encryption.ErrCMSFormatError`: CMS format parsing error

## Performance Benchmarks

### Encryption Performance (100KB document)
```
Algorithm           Encrypt Time  Decrypt Time  Encrypted Size  Method
RSA-2048           ~8ms          ~2ms          ~100KB + 256B   Envelope
RSA-3072           ~15ms         ~4ms          ~100KB + 384B   Envelope
RSA-4096           ~30ms         ~8ms          ~100KB + 512B   Envelope
ECDSA-P256         ~3ms          ~5ms          ~100KB + 64B    Envelope
ECDSA-P384         ~5ms          ~8ms          ~100KB + 96B    Envelope
Ed25519            ~2ms          ~3ms          ~100KB + 64B    Envelope
```

### Direct Encryption Limits
```
RSA-2048:  ~190 bytes maximum
RSA-3072:  ~318 bytes maximum
RSA-4096:  ~446 bytes maximum
ECDSA:     Not supported (uses envelope)
Ed25519:   Not supported (uses envelope)
```

### CMS Format Overhead
```
Base encrypted data:     Variable (depends on content)
CMS structure overhead:  ~50-200 bytes
Certificate embedding:   ~800-2000 bytes (optional)
Metadata attributes:     ~20-100 bytes (optional)
```

### Key Performance Insights
- **Ed25519**: Best overall performance with modern security
- **ECDSA**: Good balance of performance and standards compliance
- **RSA**: Maximum compatibility but higher computational cost
- **Envelope Encryption**: Consistently good performance for any data size
- **CMS Format**: Minimal overhead with maximum interoperability

---

For complete working examples, see the `main.go` file in this directory.
For integration with other modules, see the main project [README](../../README.md).