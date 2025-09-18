# Signing Module Documentation

Complete documentation for the GoPKI Signing module, demonstrating hybrid approach document signing and signature verification with multi-algorithm support.

## Table of Contents
- [Overview](#overview)
- [Core Features](#core-features)
- [Hybrid Architecture](#hybrid-architecture)
- [Supported Algorithms](#supported-algorithms)
- [Signature Formats](#signature-formats)
- [Security & Best Practices](#security--best-practices)
- [Integration Examples](#integration-examples)

## Overview

The Signing module provides comprehensive document signing and signature verification using a hybrid approach that maximizes compatibility and performance. It supports RSA, ECDSA, and Ed25519 algorithms with industry-standard PKCS#7/CMS format for RSA/ECDSA and optimized raw signatures for Ed25519.

### Key Design Principles
- **Hybrid Approach**: PKCS#7/CMS for RSA/ECDSA, raw signatures for Ed25519
- **Type Safety**: Compile-time type checking through Go generics
- **Standards Compliance**: Industry-standard PKCS#7/CMS using Smallstep library
- **Performance Optimized**: Algorithm-specific optimizations for maximum speed
- **Certificate Integration**: Seamless integration with certificate module

## Core Features

### 1. Multi-Algorithm Signing
```go
// RSA signing with PKCS#7 format
rsaManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
signature, err := signing.SignData(data, rsaManager.KeyPair(), certificate)

// ECDSA signing with PKCS#7 format
ecdsaManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
signature, err := signing.SignData(data, ecdsaManager.KeyPair(), certificate)

// Ed25519 signing with raw format (hybrid approach)
ed25519Manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair](algo.Ed25519Config{})
signature, err := signing.SignData(data, ed25519Manager.KeyPair(), certificate)
```

### 2. Advanced Signing Options
```go
opts := signing.SignOptions{
    HashAlgorithm:      crypto.SHA256,
    Format:             signing.FormatPKCS7Detached,
    IncludeCertificate: true,
    IncludeChain:       true,
    ExtraCertificates:  []*x509.Certificate{intermediateCert},
    Attributes: map[string]interface{}{
        "version": "1.0",
        "author":  "John Doe",
    },
}
signature, err := signing.SignDocument(data, keyPair, certificate, opts)
```

### 3. Comprehensive Verification
```go
// Standard verification
err := signing.VerifySignature(data, signature, signing.DefaultVerifyOptions())

// Chain verification with trusted roots
verifyOpts := signing.DefaultVerifyOptions()
verifyOpts.VerifyChain = true
verifyOpts.Roots = rootCertPool
err := signing.VerifySignature(data, signature, verifyOpts)

// Detached signature verification
err := signing.VerifyDetachedSignature(data, sigBytes, certificate, crypto.SHA256)
```

### 4. File Operations
```go
// Sign file directly
signature, err := signing.SignFile("document.pdf", keyPair, certificate)

// Stream signing for large files
signature, err := signing.SignStream(fileReader, keyPair, certificate)
```

## Hybrid Architecture

### Architecture Overview
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

### Format Selection Logic
- **RSA & ECDSA**: Automatic PKCS#7/CMS format selection
- **Ed25519**: Raw signature format (RFC 8419 not yet implemented in libraries)
- **API Transparency**: Same function calls for all algorithms
- **Format Detection**: Automatic format detection during verification

## Supported Algorithms

### RSA (Rivest-Shamir-Adleman)
- **Key Sizes**: 2048, 3072, 4096 bits (minimum 2048 enforced)
- **Hash Algorithms**: SHA-256, SHA-384, SHA-512 (auto-selected based on key size)
- **Format**: PKCS#7/CMS (attached and detached)
- **Library**: Smallstep PKCS#7
- **Use Cases**: Maximum compatibility, legacy systems, enterprise PKI

```go
// RSA signing examples
rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
signature, err := signing.SignData(data, rsaManager.KeyPair(), certificate)
// Automatically uses PKCS#7 format with SHA-256
```

### ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Curves**: P-256, P-384, P-521
- **Hash Algorithms**: SHA-256 (P-256), SHA-384 (P-384), SHA-512 (P-521)
- **Format**: PKCS#7/CMS (attached and detached)
- **Library**: Smallstep PKCS#7
- **Use Cases**: Modern PKI, TLS certificates, smaller signature sizes

```go
// ECDSA signing examples
ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
signature, err := signing.SignData(data, ecdsaManager.KeyPair(), certificate)
// Automatically uses PKCS#7 format with appropriate hash algorithm
```

### Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Size**: Fixed 256-bit keys
- **Hash Algorithm**: SHA-512 (internal to Ed25519)
- **Format**: Raw signatures (hybrid approach)
- **Library**: Native Go crypto/ed25519
- **Use Cases**: High performance, modern applications, SSH keys

```go
// Ed25519 signing examples
ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair](algo.Ed25519Config{})
signature, err := signing.SignData(data, ed25519Manager.KeyPair(), certificate)
// Automatically uses raw signature format for maximum performance
```

## Signature Formats

### Format Comparison Matrix

| Algorithm | Format | Library | Standards | Certificate Embedding | Chain Support |
|-----------|--------|---------|-----------|----------------------|---------------|
| **RSA** | PKCS#7/CMS | Smallstep | ✅ RFC 2315/5652 | ✅ Yes | ✅ Yes |
| **ECDSA** | PKCS#7/CMS | Smallstep | ✅ RFC 2315/5652 | ✅ Yes | ✅ Yes |
| **Ed25519** | Raw | Native Go | ⚠️ RFC 8419 pending | ❌ No | ❌ No |

### PKCS#7/CMS Format (RSA & ECDSA)
- **Standard**: RFC 2315 (PKCS#7) and RFC 5652 (CMS)
- **Library**: Smallstep actively maintained fork
- **Features**: Certificate embedding, chain support, metadata attributes
- **Modes**: Attached (data included) and detached (data separate)

```go
// Attached PKCS#7 (data included in signature)
opts := signing.SignOptions{
    Format:             signing.FormatPKCS7,
    IncludeCertificate: true,
    Detached:           false,
}

// Detached PKCS#7 (data separate from signature)
opts := signing.SignOptions{
    Format:             signing.FormatPKCS7Detached,
    IncludeCertificate: true,
    Detached:           true,
}
```

### Raw Format (Ed25519)
- **Reason**: RFC 8419 (Ed25519 in CMS) not implemented by available libraries
- **Format**: Direct signature bytes (64 bytes)
- **Performance**: Maximum speed with minimal overhead
- **Verification**: Direct Ed25519 signature verification

```go
// Ed25519 automatically uses raw format
signature, err := signing.SignData(data, ed25519KeyPair, certificate)
// signature.Format will be signing.FormatPKCS7Detached (for API consistency)
// But signature.Data contains raw 64-byte Ed25519 signature
```

## Security & Best Practices

### Algorithm Selection Guidelines

| Use Case | Recommended Algorithm | Reason |
|----------|----------------------|--------|
| **New Applications** | Ed25519 | Best performance and security |
| **Enterprise PKI** | RSA 3072+ or ECDSA P-256+ | Standards compliance |
| **Legacy Compatibility** | RSA 2048+ | Maximum compatibility |
| **High Security** | ECDSA P-384+ or RSA 4096+ | Enhanced security |

### Hash Algorithm Selection
The module automatically selects appropriate hash algorithms:

```go
// Automatic hash selection based on algorithm and key size
func GetHashAlgorithm(algo SignatureAlgorithm, keySize int) crypto.Hash {
    switch algo {
    case AlgorithmRSA:
        if keySize >= 3072 {
            return crypto.SHA384  // RSA 3072+ uses SHA-384
        }
        return crypto.SHA256      // RSA 2048 uses SHA-256
    case AlgorithmECDSA:
        if keySize >= 384 {
            return crypto.SHA384  // P-384+ uses SHA-384
        }
        return crypto.SHA256      // P-256 uses SHA-256
    case AlgorithmEd25519:
        return crypto.SHA512      // Ed25519 uses SHA-512 internally
    }
}
```

### Verification Security
```go
// Comprehensive verification options
verifyOpts := signing.VerifyOptions{
    RequiredKeyUsage:    x509.KeyUsageDigitalSignature,
    RequiredExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
    VerifyChain:         true,
    Roots:              trustedRootCerts,
    Intermediates:      intermediateCerts,
    VerifyTime:         time.Now(),
}
```

### Tamper Detection
The module provides comprehensive tamper detection:
- **Data Integrity**: Any modification to signed data is detected
- **Signature Integrity**: Signature tampering is immediately detected
- **Certificate Validation**: Wrong certificate usage is prevented
- **Chain Validation**: Complete certificate chain verification

## Integration Examples

### Certificate Module Integration
```go
// Generate key pair for signing
keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
keyPair := keyManager.KeyPair()

// Create signing certificate
certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "Document Signer"},
    ValidFor: 365 * 24 * time.Hour,
})

// Sign document
signature, err := signing.SignData(document, keyPair, certificate)
```

### Multi-Party Signing Workflow
```go
// Create multiple signers with different algorithms
signers := []struct {
    name    string
    keyPair interface{}
    cert    *cert.Certificate
}{
    {"Alice", rsaKeyPair, rsaCert},       // RSA with PKCS#7
    {"Bob", ecdsaKeyPair, ecdsaCert},     // ECDSA with PKCS#7
    {"Charlie", ed25519KeyPair, ed25519Cert}, // Ed25519 with raw
}

// Collect signatures from all parties
var signatures []*signing.Signature
for _, signer := range signers {
    sig, err := signing.SignData(document, signer.keyPair, signer.cert)
    signatures = append(signatures, sig)
}

// Verify all signatures
for _, sig := range signatures {
    err := signing.VerifySignature(document, sig, signing.DefaultVerifyOptions())
    // Each signature verified using appropriate format automatically
}
```

### Certificate Chain Signing
```go
// Create CA certificate
caKeyPair, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize3072)
caCert, err := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "Example CA"},
    MaxPathLen: 1,
    ValidFor: 10 * 365 * 24 * time.Hour,
})

// Create signing certificate signed by CA
signerKeyPair, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
signerCert, err := cert.SignCertificate(caCert, caKeyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "Document Signer"},
    ValidFor: 2 * 365 * 24 * time.Hour,
}, signerKeyPair.PublicKey)

// Sign with certificate chain
opts := signing.SignOptions{
    IncludeCertificate: true,
    IncludeChain:       true,
    ExtraCertificates:  []*x509.Certificate{caCert.Certificate},
}
signature, err := signing.SignDocument(document, signerKeyPair, signerCert, opts)

// Verify with chain validation
verifyOpts := signing.DefaultVerifyOptions()
verifyOpts.VerifyChain = true
verifyOpts.Roots = x509.NewCertPool()
verifyOpts.Roots.AddCert(caCert.Certificate)
err = signing.VerifySignature(document, signature, verifyOpts)
```

### Performance Testing Integration
```go
// Algorithm performance comparison
algorithms := []struct {
    name    string
    keyPair interface{}
    cert    *cert.Certificate
}{
    {"RSA-2048", rsaKeyPair, rsaCert},
    {"ECDSA-P256", ecdsaKeyPair, ecdsaCert},
    {"Ed25519", ed25519KeyPair, ed25519Cert},
}

testData := make([]byte, 100*1024) // 100KB test document

for _, alg := range algorithms {
    // Measure signing time
    startTime := time.Now()
    signature, err := signing.SignData(testData, alg.keyPair, alg.cert)
    signTime := time.Since(startTime)

    // Measure verification time
    startTime = time.Now()
    err = signing.VerifySignature(testData, signature, signing.DefaultVerifyOptions())
    verifyTime := time.Since(startTime)

    fmt.Printf("%-12s Sign: %-8v Verify: %-8v Size: %d bytes\n",
        alg.name, signTime, verifyTime, len(signature.Data))
}
```

## Error Handling

### Common Error Patterns
```go
// Signing with proper error handling
signature, err := signing.SignData(data, keyPair, certificate)
if err != nil {
    if errors.Is(err, signing.ErrMissingPrivateKey) {
        return fmt.Errorf("private key required: %w", err)
    }
    if errors.Is(err, signing.ErrMissingCertificate) {
        return fmt.Errorf("certificate required: %w", err)
    }
    return fmt.Errorf("signing failed: %w", err)
}

// Verification with error handling
err = signing.VerifySignature(data, signature, opts)
if err != nil {
    if errors.Is(err, signing.ErrVerificationFailed) {
        return fmt.Errorf("signature verification failed: %w", err)
    }
    if errors.Is(err, signing.ErrCertificateExpired) {
        return fmt.Errorf("certificate expired: %w", err)
    }
    return fmt.Errorf("verification error: %w", err)
}
```

### Error Types
- `signing.ErrInvalidSignature`: Malformed signature data
- `signing.ErrMissingPrivateKey`: Private key not provided
- `signing.ErrMissingCertificate`: Certificate not provided
- `signing.ErrVerificationFailed`: Cryptographic verification failed
- `signing.ErrCertificateExpired`: Certificate validity period expired
- `signing.ErrCertificateNotYetValid`: Certificate not yet valid
- `signing.ErrUnsupportedAlgorithm`: Unsupported signature algorithm
- `signing.ErrUnsupportedFormat`: Unsupported signature format

## Performance Benchmarks

### Signing Performance (100KB document)
```
Algorithm     Sign Time    Verify Time   Signature Size
Ed25519       ~0.5ms      ~1.0ms        64 bytes
ECDSA-P256    ~2.0ms      ~3.0ms        ~64 bytes + PKCS#7 overhead
ECDSA-P384    ~3.0ms      ~4.0ms        ~96 bytes + PKCS#7 overhead
RSA-2048      ~5.0ms      ~1.0ms        ~256 bytes + PKCS#7 overhead
RSA-3072      ~12.0ms     ~2.0ms        ~384 bytes + PKCS#7 overhead
RSA-4096      ~25.0ms     ~3.0ms        ~512 bytes + PKCS#7 overhead
```

### Key Performance Insights
- **Ed25519**: Fastest overall performance with smallest signatures
- **ECDSA**: Good balance of security, speed, and standards compliance
- **RSA**: Maximum compatibility but slower performance
- **PKCS#7 Overhead**: ~200-500 bytes additional metadata and structure

### Format Performance
```
Operation              Time      Note
PKCS#7 Creation       ~1ms      RSA/ECDSA format generation
PKCS#7 Parsing        ~0.5ms    Signature format parsing
Raw Ed25519 Sign      ~0.1ms    Direct signature generation
Raw Ed25519 Verify    ~0.3ms    Direct signature verification
Certificate Chain     +2ms      Additional chain validation time
```

---

For complete working examples, see the `main.go` file in this directory.
For integration with other modules, see the main project [README](../../README.md).