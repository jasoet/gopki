# Algorithm Selection Guide

**Comprehensive guide to choosing the right cryptographic algorithms for your use case.**

## Quick Decision Tree

```
Need to generate keys?
│
├─ Maximum compatibility needed?
│  └─ YES → RSA 2048 or 3072
│
├─ High performance priority?
│  └─ YES → Ed25519
│
├─ Modern cryptography preferred?
│  └─ YES → ECDSA P-256 or Ed25519
│
├─ Certificate-based encryption?
│  └─ YES → RSA or ECDSA (not Ed25519)
│
├─ Large data encryption?
│  └─ YES → Envelope encryption (any algorithm)
│
└─ Default recommendation
   └─ ECDSA P-256 (best balance)
```

## Algorithm Comparison

### RSA (Rivest-Shamir-Adleman)

**Key Sizes:** 2048, 3072, 4096 bits

**Strengths:**
- ✅ Maximum compatibility across all systems
- ✅ Well-understood and trusted
- ✅ Direct encryption support
- ✅ Works with all features (certificates, signing, encryption)

**Weaknesses:**
- ❌ Slowest key generation (2048: ~50-100ms, 4096: ~1-2s)
- ❌ Largest key sizes (2KB-4KB)
- ❌ Direct encryption limited by key size (~190 bytes for 2048-bit)

**Use Cases:**
- Legacy system compatibility
- Certificate-based encryption workflows
- Long-term archival (use 3072 or 4096)
- When ECDSA/Ed25519 not available

**GoPKI Support:**
```go
import "github.com/jasoet/gopki/keypair/algo"

// Generation
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)  // 2048 bits
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize3072)  // 3072 bits
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize4096)  // 4096 bits

// Signing: ✅ Full support
// Encryption: ✅ RSA-OAEP, Envelope
// Certificates: ✅ Full support
// SSH: ✅ Full support
```

### ECDSA (Elliptic Curve Digital Signature Algorithm)

**Curves:** P-224, P-256, P-384, P-521

**Strengths:**
- ✅ Smaller keys than RSA (256-bit ≈ 3072-bit RSA security)
- ✅ Fast key generation (~5-10ms for P-256)
- ✅ Modern cryptography
- ✅ Good performance
- ✅ ECDH key agreement for encryption
- ✅ Full certificate support

**Weaknesses:**
- ⚠️ Less compatible than RSA (but widely supported now)
- ⚠️ Requires key agreement for encryption (ECDH)

**Use Cases:**
- Modern applications
- Mobile and IoT (memory constrained)
- High-performance signing
- Certificate-based encryption
- General-purpose cryptography

**GoPKI Support:**
```go
// Generation
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P224)  // 224 bits
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)  // 256 bits (recommended)
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P384)  // 384 bits
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P521)  // 521 bits

// Signing: ✅ Full support
// Encryption: ✅ ECDH + AES-GCM, Envelope
// Certificates: ✅ Full support
// SSH: ✅ Full support
```

**Recommended Curves:**
- **P-256**: Best balance, widely supported
- **P-384**: Higher security for sensitive data
- **P-521**: Maximum security (overkill for most)

### Ed25519 (Edwards-curve Digital Signature Algorithm)

**Key Size:** 256 bits (fixed)

**Strengths:**
- ✅ **Fastest** key generation (~1-2ms)
- ✅ **Fastest** signing (~0.1ms)
- ✅ **Smallest** key size (32 bytes private, 32 bytes public)
- ✅ Immune to timing attacks
- ✅ Deterministic signatures
- ✅ X25519 key agreement for encryption
- ✅ Modern, well-analyzed algorithm

**Weaknesses:**
- ⚠️ Less compatibility than RSA/ECDSA (but improving)
- ❌ **Certificate-based encryption limitations** (public-key-only encryption not supported)

**Use Cases:**
- High-performance applications
- SSH keys (most popular modern choice)
- API signing/verification
- Memory-constrained environments
- When using full key pairs (not just certificates)

**GoPKI Support:**
```go
// Generation
keyPair, _ := algo.GenerateEd25519KeyPair()

// Signing: ✅ Full support (fastest)
// Encryption: ✅ X25519 + AES-GCM (key-pair based), Envelope (key-pair based)
// Certificates: ⚠️ Signing only, not encryption
// SSH: ✅ Full support (most popular for SSH)
```

**Ed25519 Limitation:**
```go
// ❌ Certificate-based encryption NOT supported
encrypted, err := encryption.EncryptForCertificate(data, ed25519Cert, opts)
// Returns error: Ed25519 certificate encryption not supported

// ✅ Key-pair encryption SUPPORTED
encrypted, err := asymmetric.EncryptWithEd25519(data, ed25519KeyPair, opts)
// Works perfectly!
```

## Performance Comparison

### Key Generation

| Algorithm | Time (approx) | Memory |
|-----------|--------------|---------|
| **Ed25519** | 1-2ms | ~64 bytes |
| **ECDSA P-256** | 5-10ms | ~100 bytes |
| **ECDSA P-384** | 10-20ms | ~200 bytes |
| **RSA-2048** | 50-100ms | ~2KB |
| **RSA-4096** | 1-2s | ~4KB |

**Winner**: Ed25519 (50-100x faster than RSA-2048)

### Signing Operation

| Algorithm | Time (1KB data) | Signature Size |
|-----------|-----------------|----------------|
| **Ed25519** | ~0.1ms | 64 bytes |
| **ECDSA P-256** | ~1ms | ~72 bytes |
| **RSA-2048** | ~1ms | 256 bytes |

**Winner**: Ed25519 (10x faster, smallest signature)

### Encryption (via Envelope)

| Algorithm | 1KB | 1MB | 100MB |
|-----------|-----|-----|-------|
| **X25519+AES** | ~1ms | ~12ms | ~1.2s |
| **ECDH+AES** | ~2ms | ~15ms | ~1.5s |
| **RSA Envelope** | ~2ms | ~15ms | ~1.5s |

**Winner**: X25519 (Ed25519-based, 20% faster)

## Security Comparison

### Security Levels

| Algorithm | Key Size | Equivalent Symmetric | Notes |
|-----------|----------|---------------------|-------|
| **RSA-2048** | 2048 bits | ~112 bits | Minimum recommended |
| **RSA-3072** | 3072 bits | ~128 bits | Long-term security |
| **RSA-4096** | 4096 bits | ~152 bits | High security |
| **ECDSA P-256** | 256 bits | ~128 bits | Standard security |
| **ECDSA P-384** | 384 bits | ~192 bits | High security |
| **ECDSA P-521** | 521 bits | ~256 bits | Very high security |
| **Ed25519** | 256 bits | ~128 bits | Modern, timing-safe |

### Security Properties

| Property | RSA | ECDSA | Ed25519 |
|----------|-----|-------|---------|
| **Timing Attack Resistant** | ⚠️ Implementation dependent | ⚠️ Implementation dependent | ✅ By design |
| **Side-Channel Resistant** | ⚠️ Difficult | ⚠️ Difficult | ✅ Easier |
| **Deterministic Signatures** | ❌ No | ⚠️ Optional (RFC 6979) | ✅ Always |
| **Quantum Resistant** | ❌ No | ❌ No | ❌ No |
| **Well-Analyzed** | ✅✅✅ Decades | ✅✅ Years | ✅ Years |

## Use Case Recommendations

### SSH Keys

**Recommendation**: **Ed25519** (first choice), ECDSA P-256 (alternative)

**Rationale**:
- Ed25519 is the modern standard for SSH
- Fastest key generation and smallest keys
- Excellent security properties
- Widely supported by OpenSSH

```go
keyPair, _ := algo.GenerateEd25519KeyPair()
manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
manager.SaveToSSH("~/.ssh/id_ed25519", "~/.ssh/id_ed25519.pub", "user@host", "")
```

### Web Server Certificates (TLS/HTTPS)

**Recommendation**: **ECDSA P-256** (first choice), RSA-2048 (compatibility)

**Rationale**:
- ECDSA widely supported by browsers
- Smaller certificates and faster handshakes
- RSA for legacy client compatibility

```go
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    DNSNames: []string{"example.com", "www.example.com"},
    ...
})
```

### Code Signing

**Recommendation**: **RSA-3072** or **RSA-4096**

**Rationale**:
- Maximum compatibility with signing tools
- Long-term validity requirements
- Industry standard for code signing

```go
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize3072)
```

### API Authentication (JWT, etc.)

**Recommendation**: **Ed25519** (first choice), ECDSA P-256 (alternative)

**Rationale**:
- Fastest signing/verification
- Smallest signature size
- Modern APIs support Ed25519

```go
keyPair, _ := algo.GenerateEd25519KeyPair()
signature, _ := signing.SignDocument(apiPayload, keyPair, certificate)
```

### Document Signing

**Recommendation**: **ECDSA P-256** (balance), Ed25519 (performance)

**Rationale**:
- PKCS#7 compatibility with ECDSA
- Fast signing with Ed25519
- Choice depends on compatibility needs

```go
// ECDSA for broad compatibility
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)

// Ed25519 for performance
keyPair, _ := algo.GenerateEd25519KeyPair()
```

### Data Encryption (Certificate-Based)

**Recommendation**: **ECDSA P-256** (first choice), RSA-2048 (compatibility)

**Rationale**:
- ECDSA supports certificate-based encryption
- Ed25519 has limitations with certificates
- Use envelope encryption for large data

```go
// ECDSA - works with certificates
ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
cert, _ := cert.CreateSelfSignedCertificate(ecdsaKeys, ...)
encrypted, _ := encryption.EncryptForCertificate(data, cert.Certificate, opts)

// RSA - maximum compatibility
rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
```

### Data Encryption (Key-Pair Based)

**Recommendation**: **Ed25519** (first choice), ECDSA P-256 (alternative)

**Rationale**:
- X25519 (Ed25519-based) is fastest
- No certificate limitations
- Excellent for direct key-pair encryption

```go
keyPair, _ := algo.GenerateEd25519KeyPair()
encrypted, _ := asymmetric.EncryptWithEd25519(data, keyPair, opts)
```

### Large File Encryption

**Recommendation**: **Envelope Encryption** (any algorithm)

**Rationale**:
- Hybrid encryption handles unlimited size
- Algorithm choice matters less (symmetric encryption dominates)
- ECDSA or Ed25519 for DEK encryption

```go
// Any algorithm works, ECDSA recommended
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
cert, _ := cert.CreateSelfSignedCertificate(keyPair, ...)
encrypted, _ := envelope.EncryptWithCertificate(largeData, cert, opts)
```

### Multi-Recipient Encryption

**Recommendation**: **Envelope Encryption** with **ECDSA P-256** or **RSA-2048**

**Rationale**:
- Envelope encryption optimized for multiple recipients
- ECDSA or RSA for certificate-based workflows
- Each recipient gets encrypted DEK

```go
recipients := []*x509.Certificate{cert1, cert2, cert3}
encrypted, _ := envelope.CreateEnvelope(data, recipients, opts)
```

## Algorithm Migration Strategies

### Migrating from RSA to ECDSA

```go
// Old: RSA
oldKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// New: ECDSA
newKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)

// Benefits:
// - 80% smaller keys
// - 10x faster key generation
// - Similar signing performance
// - Full certificate support
```

### Migrating from RSA/ECDSA to Ed25519

```go
// Old: RSA or ECDSA
oldKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// New: Ed25519
newKeys, _ := algo.GenerateEd25519KeyPair()

// Benefits:
// - 50-100x faster key generation
// - 10x faster signing
// - Smallest key size
// - Best for SSH, API signing

// Limitations:
// - Certificate-based encryption not supported
// - Use key-pair encryption instead
```

## OpenSSL Compatibility

### Full Compatibility

| Algorithm | OpenSSL Compatibility |
|-----------|----------------------|
| **RSA** | ✅ 100% (all operations) |
| **ECDSA** | ✅ 100% (all operations) |
| **Ed25519** | ✅ 95% (PKCS#7 limitations) |

### Specific Features

| Feature | RSA | ECDSA | Ed25519 |
|---------|-----|-------|---------|
| **Certificates** | ✅ 100% | ✅ 100% | ✅ 100% |
| **Raw Signatures** | ✅ 100% | ✅ 100% | ✅ 100% |
| **PKCS#7 Signatures** | ✅ 100% | ✅ 100% | ⚠️ Limited* |
| **Envelope Encryption** | ✅ 100% | ✅ GoPKI** | ✅ GoPKI** |
| **SSH Keys** | ✅ 100% | ✅ 100% | ✅ 100% |

*OpenSSL has limited Ed25519 PKCS#7 support (not GoPKI limitation)
**OpenSSL smime only supports RSA; ECDSA/Ed25519 envelope is GoPKI-specific

## Best Practices Summary

1. **Default Choice**: ECDSA P-256 (best balance)
2. **Maximum Performance**: Ed25519
3. **Maximum Compatibility**: RSA-2048
4. **High Security**: RSA-3072, ECDSA P-384
5. **SSH Keys**: Ed25519
6. **Web Certificates**: ECDSA P-256
7. **Code Signing**: RSA-3072/4096
8. **Certificate Encryption**: ECDSA P-256 or RSA-2048
9. **Key-Pair Encryption**: Ed25519
10. **Large Data**: Envelope (any algorithm)

## Further Reading

- **Architecture**: [`ARCHITECTURE.md`](ARCHITECTURE.md) - System design
- **OpenSSL Compatibility**: [`OPENSSL_COMPAT.md`](OPENSSL_COMPAT.md) - Integration guide
- **Examples**: [`examples/*/doc.md`](../examples/) - Working code examples
- **Compatibility Report**: [`COMPATIBILITY_REPORT.md`](COMPATIBILITY_REPORT.md) - Test results