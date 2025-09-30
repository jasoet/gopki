# AI Agent Navigation Guide

**Comprehensive guide for AI assistants working on the GoPKI codebase.**

## Quick Start for New AI Agents

**First 5 Files to Read (in order):**
1. [`README.md`](../README.md) - Project overview and AI instructions
2. [`CLAUDE.md`](../CLAUDE.md) - Development guidelines and patterns
3. This file (`docs/AI_NAVIGATION.md`) - Navigation guide
4. [`keypair/README.md`](../keypair/README.md) - Foundation module
5. [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) - System design

## 📚 Learning Through Examples

**AI agents learn best from working examples.** GoPKI includes comprehensive, production-ready examples for all features:

| Module | Example | Documentation | Key Topics |
|--------|---------|---------------|------------|
| **Keypair** | [`examples/keypair/main.go`](../examples/keypair/main.go) | [`doc.md`](../examples/keypair/doc.md) | All algorithms, format conversion, SSH keys, Manager API |
| **Certificates** | [`examples/certificates/main.go`](../examples/certificates/main.go) | [`doc.md`](../examples/certificates/doc.md) | CA hierarchies, signing, SANs, chain verification |
| **Signing** | [`examples/signing/main.go`](../examples/signing/main.go) | [`doc.md`](../examples/signing/doc.md) | Multi-algorithm signing, PKCS#7, verification workflows |
| **Encryption** | [`examples/encryption/main.go`](../examples/encryption/main.go) | [`doc.md`](../examples/encryption/doc.md) | All algorithms, envelope encryption, OpenSSL compatibility |
| **PKCS#12** | [`examples/pkcs12/main.go`](../examples/pkcs12/main.go) | [`doc.md`](../examples/pkcs12/doc.md) | Certificate bundling, cross-platform P12 files |

**Running Examples:**
```bash
task examples:run           # Run all examples
task examples:keypair       # Specific module
task examples:encryption    # Show encryption patterns
```

**Example Files Are:**
- ✅ **Production-ready** - Real-world usage patterns
- ✅ **Comprehensive** - Cover all major features
- ✅ **Well-documented** - Inline comments and separate doc files
- ✅ **Tested** - Verified to work with real data
- ✅ **Referenced** - Linked throughout documentation

**When to Use Examples:**
- **Learning API** - See complete workflows
- **Debugging issues** - Compare with working code
- **Adding features** - Follow established patterns
- **Understanding flows** - See module interactions
- **Testing changes** - Verify behavior matches examples

## Navigation by Task Type

### 1. Key Generation/Management Tasks

**Read First:**
- [`keypair/README.md`](../keypair/README.md) - Complete API documentation
- `keypair/keypair.go:50-150` - **CRITICAL**: Type constraints

**Key Files:**
- `keypair/keypair.go` - Manager and core functionality
- `keypair/algo/rsa.go` - RSA implementation
- `keypair/algo/ecdsa.go` - ECDSA implementation
- `keypair/algo/ed25519.go` - Ed25519 implementation

**Working Examples:**
- [`examples/keypair/main.go`](../examples/keypair/main.go) - Complete key generation examples
- [`examples/keypair/doc.md`](../examples/keypair/doc.md) - Detailed documentation

**Common Modifications:**
- Adding new algorithm → Follow `algo/rsa.go` pattern, review examples first
- Format conversion → Check format conversion functions in `keypair.go`, see examples for usage patterns
- File operations → Review file operation functions in `keypair.go`, check examples for file handling patterns

### 2. Encryption Tasks

**Read First:**
- [`encryption/README.md`](../encryption/README.md) - Most comprehensive module doc
- `encryption/envelope/envelope.go:50-150` - Envelope structure
- [`docs/OPENSSL_COMPAT.md`](OPENSSL_COMPAT.md) - OpenSSL integration

**Key Files:**
- `encryption/encryption.go` - High-level API
- `encryption/envelope/envelope.go` - **MOST COMPLEX** - Envelope encryption logic
- `encryption/cms.go` - CMS format support
- `encryption/asymmetric/asymmetric.go` - Core asymmetric encryption logic

**Critical Tests:**
- `encryption/envelope/cms_cycle_test.go` - Tests full cycle
- `compatibility/encryption/encryption_test.go` - OpenSSL tests

**Working Examples:**
- [`examples/encryption/main.go`](../examples/encryption/main.go) - Complete encryption examples
- [`examples/encryption/doc.md`](../examples/encryption/doc.md) - Detailed guide

**Common Modifications:**
- OpenSSL compatibility → Check OpenSSL mode in `envelope/envelope.go`
- New algorithm → Add to `asymmetric/` directory
- CMS format issues → Review `DecodeFromCMS` function in `cms.go`

### 3. Digital Signature Tasks

**Read First:**
- [`signing/README.md`](../signing/README.md) - Signing API overview
- `signing/formats/pkcs7.go` - PKCS#7 format support

**Key Files:**
- `signing/signing.go` - Core signing API
- `signing/signer.go` - Signer implementations
- `signing/verifier.go` - Verification logic

**Working Examples:**
- [`examples/signing/main.go`](../examples/signing/main.go) - Document signing examples
- [`examples/signing/doc.md`](../examples/signing/doc.md) - PKCS#7 guide

**Common Modifications:**
- New signature format → `signing/formats/`
- Algorithm support → Check `signer.go` dispatching

### 4. Certificate Tasks

**Read First:**
- [`cert/README.md`](../cert/README.md) - Certificate operations
- Examples in `examples/certificates/main.go`

**Key Files:**
- `cert/cert.go` - Certificate creation
- `cert/ca.go` - CA operations

**Working Examples:**
- [`examples/certificates/main.go`](../examples/certificates/main.go) - CA hierarchy examples
- [`examples/certificates/doc.md`](../examples/certificates/doc.md) - Certificate guide

**Common Modifications:**
- CA hierarchy → `ca.go` SignCertificate function
- SAN extensions → `cert.go` certificate request handling

### 5. PKCS#12 Tasks

**Read First:**
- [`pkcs12/README.md`](../pkcs12/README.md) - P12 operations

**Key Files:**
- `pkcs12/pkcs12.go` - Complete P12 implementation

**Working Examples:**
- [`examples/pkcs12/main.go`](../examples/pkcs12/main.go) - P12 bundling examples
- [`examples/pkcs12/doc.md`](../examples/pkcs12/doc.md) - PKCS#12 guide

### 6. Testing Tasks

**Test Organization:**
- Unit tests: `*_test.go` files in each module
- Integration tests: `examples/*/main.go`
- Compatibility tests: `compatibility/*/` with `//go:build compatibility` tag

**Running Tests:**
```bash
task test                   # All tests with race detection
task test:specific -- TestName  # Specific test
task test:compatibility     # OpenSSL/SSH compatibility
task test:coverage          # HTML coverage report
```

**Adding New Tests:**
1. Review existing test patterns in module
2. Follow table-driven test design
3. Add compatibility tests if external tool integration
4. Update coverage targets

### 7. OpenSSL Compatibility Tasks

**Read First:**
- [`docs/OPENSSL_COMPAT.md`](OPENSSL_COMPAT.md) - Complete guide
- [`docs/COMPATIBILITY_REPORT.md`](COMPATIBILITY_REPORT.md) - Test results

**Key Files:**
- `compatibility/helpers.go` - OpenSSL integration utilities
- `compatibility/encryption/encryption_test.go` - Envelope tests
- `compatibility/keypair/ssh_test.go` - SSH tests

**Adding OpenSSL Test:**
1. Create helper function in `compatibility/helpers.go`
2. Add test in relevant `compatibility/*/` directory
3. Test bidirectional compatibility (GoPKI ↔ OpenSSL)
4. Document results in `docs/COMPATIBILITY_REPORT.md`

## Code Reading Paths

### Path 1: Understanding Core Architecture

```
1. README.md → Overview
2. docs/ARCHITECTURE.md → System design
3. keypair/keypair.go:50-150 → Type constraints (CRITICAL)
4. encryption/envelope/envelope.go:50-150 → Envelope structure
5. signing/signing.go → Signature types
6. cert/cert.go → Certificate operations
```

### Path 2: Understanding Type System

```
1. keypair/keypair.go:50-150 → Generic constraints
2. keypair/algo/rsa.go:50-200 → RSA key pair structure
3. encryption/encryption.go:50-150 → Encryption types
4. signing/types.go → Signature types
```

### Path 3: Understanding OpenSSL Integration

```
1. docs/OPENSSL_COMPAT.md → Integration guide
2. compatibility/helpers.go → OpenSSL utilities
3. encryption/envelope/envelope.go:520-600 → OpenSSL mode
4. encryption/cms.go:160-180 → Format auto-detection
5. compatibility/encryption/encryption_test.go → Tests
```

### Path 4: Understanding Envelope Encryption

```
1. encryption/README.md → Module overview
2. encryption/envelope/envelope.go:50-150 → Types
3. encryption/envelope/envelope.go:180-350 → Encryption
4. encryption/envelope/envelope.go:520-600 → Decryption
5. encryption/envelope/cms_cycle_test.go → Full cycle test
```

## Critical Files Reference

### Type Definitions (Read First!)

| File | Purpose |
|------|---------|
| `keypair/keypair.go:50-150` | **Generic type constraints - START HERE** |
| `encryption/encryption.go` | Encryption types and options |
| `signing/types.go` | Signature types and options |
| `cert/types.go` | Certificate request types |

### Core Implementations

| File | Purpose |
|------|---------|
| `keypair/manager.go` | KeyPair Manager implementation |
| `encryption/envelope/envelope.go` | Envelope encryption (most complex) |
| `signing/signer.go` | Document signing |
| `cert/ca.go` | CA operations |

### Format Support

| File | Purpose |
|------|---------|
| `keypair/format/format.go` | Format type definitions |
| `encryption/cms.go` | CMS encoding/decoding |
| `signing/formats/pkcs7.go` | PKCS#7 signatures |

### Testing Infrastructure

| File | Purpose |
|------|---------|
| `compatibility/helpers.go` | OpenSSL integration utilities |
| `*/envelope/cms_cycle_test.go` | Critical CMS cycle tests |
| `compatibility/encryption/encryption_test.go` | OpenSSL envelope tests |

## Common Bug Patterns

### 1. CMS Cycle Issues

**Symptom**: Envelope encryption breaks after CMS encode/decode cycle

**Investigation Path:**
1. Read `encryption/envelope/cms_cycle_test.go` - CMS cycle tests
2. Check `DecodeFromCMS` function in `encryption/cms.go`
3. Verify envelope structure preservation
4. Test: `task test:specific -- TestCertificateEnvelopeEncryptionWithCMSCycle`

**Common Cause**: DecodeFromCMS decrypting prematurely instead of preserving structure

### 2. Type Constraint Violations

**Symptom**: Compile errors with generic types

**Investigation Path:**
1. Review `keypair/keypair.go:50-150` type constraints
2. Check function signature uses correct constraint
3. Verify all type parameters specified

**Common Cause**: Missing type parameters or wrong constraint used

### 3. OpenSSL Compatibility Failures

**Symptom**: OpenSSL can't decrypt GoPKI data or vice versa

**Investigation Path:**
1. Read `docs/OPENSSL_COMPAT.md`
2. Check `encryption/envelope/envelope.go:150-180` (OpenSSLCompatible option)
3. Verify `encryption/cms.go:160-180` (format auto-detection)
4. Test: `task test:compatibility`

**Common Causes**:
- OpenSSLCompatible flag not set
- Non-RSA certificate (OpenSSL limitation)
- Format auto-detection not working

### 4. File Permission Issues

**Symptom**: File operations fail or insecure permissions

**Investigation Path:**
1. Check file operation functions in `keypair/keypair.go`
2. Verify 0600 for private keys, 0700 for directories
3. Review atomic file operations

**Common Cause**: Not using Manager's SaveTo* methods

## Module Interaction Patterns

### Pattern 1: Key Generation → Certificate Creation

```go
// 1. Generate key pair (keypair module)
manager, _ := keypair.Generate[...]

// 2. Extract key pair
keyPair := manager.KeyPair()

// 3. Create certificate (cert module)
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, request)
```

### Pattern 2: Certificate → Encryption

```go
// 1. Have certificate (from cert module)
certificate *cert.Certificate

// 2. Encrypt for certificate (encryption module)
encrypted, _ := encryption.EncryptForCertificate(data, certificate.Certificate, opts)

// 3. Decrypt with key pair (back to keypair module)
decrypted, _ := encryption.DecryptWithKeyPair(encrypted, keyPair)
```

### Pattern 3: Key Pair → Signing → Verification

```go
// 1. Generate key pair (keypair module)
keyPair, _ := algo.GenerateRSAKeyPair(...)

// 2. Sign document (signing module)
signature, _ := signing.SignDocument(document, keyPair, certificate)

// 3. Verify signature (signing module)
err := signing.VerifySignature(document, signature, opts)
```

### Pattern 4: Full PKI Workflow

```go
// 1. Generate CA (keypair + cert)
caKeys, _ := algo.GenerateRSAKeyPair(...)
caCert, _ := cert.CreateCACertificate(caKeys, ...)

// 2. Generate server cert (keypair + cert)
serverKeys, _ := algo.GenerateRSAKeyPair(...)
serverCert, _ := cert.SignCertificate(caCert, caKeys, ..., serverKeys.PublicKey)

// 3. Bundle in P12 (pkcs12)
pkcs12.CreateP12File("server.p12", serverKeys.PrivateKey, serverCert.Certificate, chain, opts)

// 4. Use for signing (signing)
signature, _ := signing.SignDocument(document, serverKeys, serverCert)

// 5. Use for encryption (encryption)
encrypted, _ := encryption.EncryptForCertificate(data, serverCert.Certificate, opts)
```

## Performance Considerations

### Algorithm Performance

| Algorithm | Operation | Time (approx) |
|-----------|-----------|---------------|
| RSA-2048 | Generation | 50-100ms |
| RSA-2048 | Signing | ~1ms |
| ECDSA-P256 | Generation | 5-10ms |
| ECDSA-P256 | Signing | ~1ms |
| Ed25519 | Generation | 1-2ms |
| Ed25519 | Signing | ~0.1ms |

**Recommendations:**
- Ed25519 for best performance
- ECDSA for balance
- RSA for compatibility

### Encryption Performance

| Algorithm | 1KB | 1MB | 100MB |
|-----------|-----|-----|-------|
| RSA-OAEP | ~1ms | N/A | N/A |
| ECDH+AES | ~2ms | ~15ms | ~1.5s |
| X25519+AES | ~1ms | ~12ms | ~1.2s |
| Envelope | ~2ms | ~15ms | ~1.5s |

**Recommendations:**
- Envelope for all scenarios
- X25519 for best performance
- ECDH for modern systems

## Security Reminders

**When Modifying Code:**
1. ✅ Maintain minimum key sizes (RSA ≥2048)
2. ✅ Use `crypto/rand.Reader` exclusively
3. ✅ Preserve type safety (no `any` in core APIs)
4. ✅ Keep file permissions (0600 private, 0700 dirs)
5. ✅ Validate all inputs before crypto operations
6. ✅ Test OpenSSL compatibility after changes
7. ✅ Update documentation for API changes

## Getting Unstuck

**If you're stuck on:**

**Understanding type system** → Read `keypair/keypair.go:50-150` first

**Envelope encryption** → Read `encryption/README.md` AI Quick Start section

**OpenSSL compatibility** → Read `docs/OPENSSL_COMPAT.md`

**Test failures** → Check test file for expected behavior, read related `*_test.go`

**Module relationships** → Read `docs/ARCHITECTURE.md`

**Algorithm selection** → Read `docs/ALGORITHMS.md`

## Documentation Index

**Module Documentation:**
- [`keypair/README.md`](../keypair/README.md) - Foundation module
- [`encryption/README.md`](../encryption/README.md) - Most comprehensive
- [`signing/README.md`](../signing/README.md) - Digital signatures
- [`cert/README.md`](../cert/README.md) - Certificates
- [`pkcs12/README.md`](../pkcs12/README.md) - P12 bundles

**Conceptual Documentation:**
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) - System design
- [`docs/ALGORITHMS.md`](ALGORITHMS.md) - Algorithm guide
- [`docs/OPENSSL_COMPAT.md`](OPENSSL_COMPAT.md) - OpenSSL integration

**Development Documentation:**
- [`CLAUDE.md`](../CLAUDE.md) - Development guidelines
- [`docs/COMPATIBILITY_REPORT.md`](COMPATIBILITY_REPORT.md) - Test results
- [`examples/*/doc.md`](../examples/) - Example documentation

---

**Remember**: This is a type-safe, security-first library. Always preserve type constraints and security properties when making changes!