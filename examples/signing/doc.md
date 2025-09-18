# Document Signing Module

Advanced document signing and signature verification with multi-algorithm support using hybrid approach for maximum compatibility.

> 📖 **Related Documentation**: [KeyPair Module](../keypair/doc.md) | [Certificate Module](../cert/doc.md) | [Main README](../../README.md)

## Features

### 🔐 **Hybrid Signature Approach**
- **RSA & ECDSA**: Industry-standard PKCS#7/CMS format using Smallstep library
- **Ed25519**: Raw signatures (RFC 8419 not yet implemented in PKCS#7 libraries)
- **Unified API**: Same interface for all algorithms with automatic format detection

### 🛡️ **Type-Safe Design**
- **Go Generics**: Compile-time type safety consistent with other modules
- **Algorithm Detection**: Automatic signature algorithm determination from certificates
- **Error Handling**: Comprehensive error reporting with specific failure reasons

### 📋 **Certificate Integration**
- **Seamless Integration**: Works with [Certificate Module](../cert/doc.md) certificates
- **Chain Verification**: Complete certificate chain validation support
- **Metadata Support**: Custom attributes and certificate chains in signatures

### ⚡ **Performance Optimized**
- **Streaming Support**: Efficient signing of large documents via `io.Reader`
- **Algorithm Comparison**: Built-in performance testing for all algorithms
- **Memory Efficient**: Optimized for both small and large document processing

## Architecture Overview

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   RSA Signing       │    │   ECDSA Signing      │    │   Ed25519 Signing   │
│                     │    │                      │    │                     │
│ ✓ PKCS#7 Attached   │    │ ✓ PKCS#7 Attached    │    │ ✓ Raw Signatures    │
│ ✓ PKCS#7 Detached   │    │ ✓ PKCS#7 Detached    │    │ ✓ Direct Verify     │
│ ✓ Certificate Chain │    │ ✓ Certificate Chain  │    │ ✓ High Performance  │
│ ✓ Industry Standard │    │ ✓ Smaller Signatures │    │ ✓ Modern Crypto     │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
                         │
                         ▼
           ┌────────────────────────────────────┐
           │        Unified Signing API          │
           │                                    │
           │  • SignData()                      │
           │  • SignDocument()                  │
           │  • SignFile()                      │
           │  • VerifySignature()               │
           │  • VerifyWithCertificate()         │
           └────────────────────────────────────┘
```

## Quick Start

```go
package main

import (
    "crypto/x509/pkix"
    "fmt"
    "log"
    "time"

    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/signing"
)

func main() {
    // 1. Generate key pair (any algorithm)
    keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
    if err != nil {
        log.Fatal(err)
    }
    keyPair := keyManager.KeyPair()

    // 2. Create certificate
    certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Document Signer"},
        ValidFor: 365 * 24 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }

    // 3. Sign document (automatically uses PKCS#7 for RSA/ECDSA, raw for Ed25519)
    document := []byte("Important document content")
    signature, err := signing.SignData(document, keyPair, certificate)
    if err != nil {
        log.Fatal(err)
    }

    // 4. Verify signature
    err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("✓ Document signed with %s using %s format\n",
        signature.Algorithm, signature.Format)
}
```

## Algorithm Support Matrix

| Algorithm | Format | Library | Standards | Performance | Signature Size |
|-----------|--------|---------|-----------|-------------|----------------|
| **RSA-2048** | PKCS#7 | Smallstep | ✅ RFC 2315/5652 | Medium | ~256 bytes |
| **RSA-3072** | PKCS#7 | Smallstep | ✅ RFC 2315/5652 | Slow | ~384 bytes |
| **RSA-4096** | PKCS#7 | Smallstep | ✅ RFC 2315/5652 | Slowest | ~512 bytes |
| **ECDSA-P256** | PKCS#7 | Smallstep | ✅ RFC 2315/5652 | Fast | ~64 bytes |
| **ECDSA-P384** | PKCS#7 | Smallstep | ✅ RFC 2315/5652 | Fast | ~96 bytes |
| **ECDSA-P521** | PKCS#7 | Smallstep | ✅ RFC 2315/5652 | Fast | ~132 bytes |
| **Ed25519** | Raw | Native Go | ⚠️ RFC 8419 pending | Fastest | 64 bytes |

### Format Details

- **PKCS#7/CMS**: Industry standard, maximum compatibility, certificate embedding
- **Raw Ed25519**: Direct signature bytes, no container format, highest performance
- **Hybrid Approach**: Maintains API compatibility while maximizing format support

## Core API Functions

### Signing Functions
```go
// Basic signing with default options
func SignData(data []byte, keyPair KeyPairInterface, cert *cert.Certificate) (*Signature, error)

// Advanced signing with custom options
func SignDocument(data []byte, keyPair KeyPairInterface, cert *cert.Certificate, opts SignOptions) (*Signature, error)

// File signing with streaming
func SignFile(filename string, keyPair KeyPairInterface, cert *cert.Certificate) (*Signature, error)

// Stream signing for large data
func SignStream(reader io.Reader, keyPair KeyPairInterface, cert *cert.Certificate) (*Signature, error)
```

### Verification Functions
```go
// Standard verification
func VerifySignature(data []byte, signature *Signature, opts VerifyOptions) error

// Verify with specific certificate
func VerifyWithCertificate(data []byte, signature *Signature, cert *x509.Certificate, opts VerifyOptions) error

// Detached signature verification (raw signatures)
func VerifyDetachedSignature(data []byte, sigBytes []byte, cert *x509.Certificate, hashAlgo crypto.Hash) error
```

### Utility Functions
```go
// Extract certificate from signature
func ExtractCertificateFromSignature(signature *Signature) (*x509.Certificate, error)

// Get readable signature information
func GetSignatureInfo(signature *Signature) string

// Validate signature structure
func IsSignatureValid(signature *Signature) bool
```

## Advanced Features

### Certificate Chain Support
```go
opts := signing.SignOptions{
    IncludeCertificate: true,
    IncludeChain:      true,
    ExtraCertificates: []*x509.Certificate{intermediateCert, rootCert},
}
signature, err := signing.SignDocument(data, keyPair, cert, opts)
```

### Chain Verification
```go
verifyOpts := signing.DefaultVerifyOptions()
verifyOpts.VerifyChain = true
verifyOpts.Roots = rootCertPool
verifyOpts.Intermediates = intermediateCertPool
err := signing.VerifySignature(data, signature, verifyOpts)
```

### Custom Metadata
```go
opts := signing.SignOptions{
    Attributes: map[string]interface{}{
        "version":    "1.0",
        "author":     "John Doe",
        "department": "Legal",
        "timestamp":  time.Now(),
    },
}
```

## Examples Structure

The `examples/signing/` directory contains comprehensive demonstrations:

```
examples/signing/
├── main.go          # Complete examples with all algorithms
├── doc.md           # This documentation
└── output/          # Generated signatures and certificates
    ├── rsa_signature.json
    ├── ecdsa_signature.json
    ├── ed25519_signature.json
    ├── chain_signature.json
    ├── multi_signature.json
    ├── pkcs7_attached.p7s
    ├── pkcs7_detached.p7s
    └── test_document.sig
```

### Example Categories

1. **🔐 Multi-Algorithm Signing**: RSA, ECDSA, Ed25519 demonstrations
2. **📋 Advanced Options**: Certificate chains, metadata, custom hash algorithms
3. **✅ Security Testing**: Tamper detection, wrong certificate detection
4. **📝 Multi-Party Signing**: Co-signing workflows with multiple algorithms
5. **🔒 PKCS#7 Formats**: Attached vs detached signatures
6. **🚀 Performance Testing**: Algorithm comparison with timing metrics
7. **📁 File Operations**: File signing and detached signature workflows

## Security Considerations

### Tamper Detection
- **Data Integrity**: Any modification to signed data is detected
- **Signature Integrity**: Signature tampering is immediately detected
- **Certificate Validation**: Wrong certificate usage is prevented

### Best Practices
- **Hash Selection**: Automatic hash algorithm selection based on key size
- **Certificate Chains**: Enable chain verification in production environments
- **Key Size**: Use minimum 2048-bit RSA or P-256 ECDSA curves
- **Ed25519**: Preferred for new applications due to performance and security

## Performance Characteristics

Based on 100KB document testing:

```
Algorithm    Sign Time    Verify Time  Signature Size
RSA-2048     ~5ms         ~1ms         ~256 bytes
ECDSA-P256   ~2ms         ~3ms         ~64 bytes
Ed25519      ~0.5ms       ~1ms         64 bytes
```

**Key Insights:**
- **Ed25519**: Fastest signing, smallest signatures
- **ECDSA**: Good balance of speed and standards compliance
- **RSA**: Maximum compatibility, slower performance

## Testing

```bash
# Run all signing tests
go test ./signing -v

# Run specific algorithm tests
go test ./signing -v -run TestSignAndVerifyRSA
go test ./signing -v -run TestSignAndVerifyECDSA
go test ./signing -v -run TestSignAndVerifyEd25519

# Test with coverage
go test ./signing -v -cover

# Run example
cd examples/signing && go run main.go
```

## Integration with Other Modules

### KeyPair Module Integration
```go
// RSA
rsaManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
signature, _ := signing.SignData(data, rsaManager.KeyPair(), cert)

// ECDSA
ecdsaManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
signature, _ := signing.SignData(data, ecdsaManager.KeyPair(), cert)

// Ed25519
ed25519Manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair](algo.Ed25519Config{})
signature, _ := signing.SignData(data, ed25519Manager.KeyPair(), cert)
```

### Certificate Module Integration
- **Self-signed certificates**: `cert.CreateSelfSignedCertificate()`
- **CA certificates**: `cert.CreateCACertificate()`
- **Signed certificates**: `cert.SignCertificate()`
- **Certificate chains**: Full chain validation support

## Development Status

✅ **Core Features Completed**
- Multi-algorithm signing (RSA, ECDSA, Ed25519)
- PKCS#7/CMS format support (RSA, ECDSA)
- Raw signature support (Ed25519)
- Certificate integration and chain validation
- Comprehensive verification with security testing
- File operations and detached signatures
- Performance optimization and testing
- Full test coverage (78.7%)

⚠️ **Technical Limitations**
- **Ed25519 + PKCS#7**: RFC 8419 not implemented by available libraries
- **Hybrid Approach**: Different formats for different algorithms (by design)
- **Library Dependency**: Uses Smallstep PKCS#7 library for standards compliance

🔮 **Future Enhancements**
- **RFC 8419 Support**: When PKCS#7 libraries implement Ed25519
- **Timestamping**: TSA (Time Stamping Authority) integration
- **Additional Formats**: Support for other signature formats as needed

## Development Commands

Using the project's Taskfile:

```bash
# Run signing module tests
task test:signing

# Run all tests including signing
task test

# Run signing examples
cd examples/signing && go run main.go

# Format and lint
task format lint
```

---

> 📖 **Related Documentation**: [KeyPair Module](../keypair/doc.md) | [Certificate Module](../cert/doc.md) | [Main README](../../README.md)

> 🔍 **Key Point**: Ed25519 uses **raw signatures** (not PKCS#7) due to library limitations. The hybrid approach maintains API compatibility while maximizing format support.