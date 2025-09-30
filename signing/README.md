# signing/ - Digital Signatures and Verification

**Document signing with PKCS#7/CMS formats and multi-algorithm support.**

[![Test Coverage](https://img.shields.io/badge/Coverage-79.8%25-green.svg)](https://github.com/jasoet/gopki)

## Overview

Digital signature creation and verification with support for:
- **Multiple algorithms** (RSA, ECDSA, Ed25519)
- **PKCS#7/CMS formats** (attached and detached signatures)
- **Certificate chains** in signatures
- **RFC 3161 timestamp support**
- **OpenSSL signature verification** compatibility

## 🤖 AI Agent Quick Start

### File Structure

```
signing/
├── signing.go          [Core signing API]
├── signer.go           [Signer implementations]
├── verifier.go         [Verification logic]
├── formats/
│   └── pkcs7.go       [PKCS#7/CMS format support]
└── *_test.go          [Comprehensive tests - 79.8% coverage]
```

### Key Functions

| Function | Purpose |
|----------|---------|
| `SignDocument()` | Simple document signing |
| `SignData()` | Advanced signing with options |
| `VerifySignature()` | Signature verification |
| `CreatePKCS7Signature()` | PKCS#7 format creation |
| `VerifyPKCS7Signature()` | PKCS#7 verification |

### Common Tasks

**Adding new signature format:**
1. Review `formats/pkcs7.go` implementation
2. Create new format handler
3. Update `SignData()` format dispatcher
4. Add comprehensive tests
5. Test OpenSSL compatibility

### Dependencies

- **keypair/** - Key types for signing operations
- **cert/** - Certificate integration
- **go.mozilla.org/pkcs7** - PKCS#7 library

## Quick Start

```go
import (
    "github.com/jasoet/gopki/signing"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/cert"
)

// Generate key pair and certificate
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{...})

// Sign document
document := []byte("Important contract")
signature, _ := signing.SignDocument(document, keyPair, certificate)

// Verify signature
err := signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
```

## API Reference

### Signing Functions

```go
// Simple signing
func SignDocument[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate) (*Signature, error)

// Advanced signing with options
func SignData[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate, opts SignOptions) (*Signature, error)

// PKCS#7 format
func CreatePKCS7Signature[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate, detached bool) ([]byte, error)
```

### Verification Functions

```go
// Verify signature
func VerifySignature(data []byte, signature *Signature, opts VerifyOptions) error

// Verify with specific certificate
func VerifyWithCertificate(data []byte, signature *Signature, certificate *x509.Certificate) error

// Verify PKCS#7
func VerifyPKCS7Signature(data []byte, pkcs7Data []byte) (*PKCS7Info, error)
```

### Signature Options

```go
type SignOptions struct {
    HashAlgorithm      crypto.Hash        // SHA256, SHA384, SHA512
    Format             SignatureFormat    // raw, pkcs7, pkcs7-detached
    IncludeCertificate bool              // Include signer certificate
    IncludeChain       bool              // Include certificate chain
    Detached           bool              // Create detached signature
    TimestampURL       string            // TSA URL for RFC 3161 timestamp
}
```

## Signature Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| **Raw** | Algorithm-specific binary | Smallest size, simple verification |
| **PKCS#7 Attached** | Signature + document | Self-contained, larger size |
| **PKCS#7 Detached** | Signature only | Recommended, document separate |

## Testing

```bash
# Run signing tests
go test ./signing/...

# Specific tests
task test:specific -- TestSignDocument
task test:specific -- TestPKCS7Signature

# OpenSSL compatibility
task test:compatibility
```

**Test Coverage:** 79.8%

## Best Practices

1. **Use PKCS#7 Detached** for most scenarios
2. **Include Certificate Chain** for complete verification path
3. **SHA256 or Higher** for hash algorithms
4. **Ed25519 for Performance** when compatibility allows
5. **Test Verification** with different key types

## Further Reading

- **OpenSSL Compatibility**: [`docs/OPENSSL_COMPAT.md`](../docs/OPENSSL_COMPAT.md)
- **Algorithms**: [`docs/ALGORITHMS.md`](../docs/ALGORITHMS.md)
- **Examples**: [`examples/signing/main.go`](../examples/signing/main.go)
- **Compatibility Report**: [`COMPATIBILITY_REPORT.md`](../docs/COMPATIBILITY_REPORT.md)

---

**Part of [GoPKI](../README.md) - Type-Safe Cryptography for Production**