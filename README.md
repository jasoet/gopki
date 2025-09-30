# GoPKI

[![Go Version](https://img.shields.io/badge/Go-1.24.5+-blue.svg)](https://golang.org)
[![Test Coverage](https://img.shields.io/badge/Coverage-80.3%25-green.svg)](https://github.com/jasoet/gopki)
[![Go Report Card](https://goreportcard.com/badge/github.com/jasoet/gopki)](https://goreportcard.com/report/github.com/jasoet/gopki)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Production-ready Go library for PKI operations** with **type-safe cryptography through Go generics**. Full X.509, PKCS#7/CMS, PKCS#12, and SSH format support with 80.3% test coverage across 844+ tests.

## ✨ Why GoPKI?

- **🔒 Type-Safe Cryptography**: Go generics eliminate `any`/`interface{}` types for compile-time safety
- **🛡️ Security-First**: Enforced minimum key sizes, secure file permissions, memory-safe APIs
- **📜 Standards Compliant**: Full RFC compliance (X.509, CMS, PKCS#7, PKCS#12, SSH)
- **🤝 Battle-Tested**: 95%+ OpenSSL compatibility, 100% OpenSSH compatibility
- **⚡ Production Ready**: 80.3% test coverage, comprehensive CI/CD, semantic versioning

## 📦 Installation

```bash
go get github.com/jasoet/gopki
```

**Requirements**: Go 1.24.5+

## 🤖 AI Agent Instructions

**If you're an AI assistant working on this codebase, start here:**

### 📖 Comprehensive AI Navigation Guide

**For complete AI agent guidance, read:**
- **[`docs/AI_NAVIGATION.md`](docs/AI_NAVIGATION.md)** - Comprehensive navigation guide for AI assistants

This README provides a quick reference. For detailed navigation paths, common bug patterns, module interaction patterns, and troubleshooting guides, see the AI Navigation document.

### Quick Navigation by Task

| Task | Read First | Read Next | Key Files |
|------|-----------|-----------|-----------|
| **Key Generation/Management** | [`keypair/README.md`](keypair/README.md) | [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md) | `keypair/keypair.go`, `keypair/algo/*.go` |
| **Encryption Features** | [`encryption/README.md`](encryption/README.md) | [`docs/ENCRYPTION_GUIDE.md`](docs/ENCRYPTION_GUIDE.md) | `encryption/envelope/`, `encryption/asymmetric/` |
| **Digital Signatures** | [`signing/README.md`](signing/README.md) | [`docs/OPENSSL_COMPAT.md`](docs/OPENSSL_COMPAT.md) | `signing/signer.go`, `signing/formats/` |
| **Certificate Operations** | [`cert/README.md`](cert/README.md) | Certificate examples | `cert/cert.go`, `cert/ca.go` |
| **PKCS#12 Files** | [`pkcs12/README.md`](pkcs12/README.md) | Module tests | `pkcs12/pkcs12.go` |
| **OpenSSL Compatibility** | [`docs/OPENSSL_COMPAT.md`](docs/OPENSSL_COMPAT.md) | `compatibility/` tests | `compatibility/helpers.go` |
| **Testing** | `Taskfile.yml` | Module-specific tests | `*_test.go` files |

### Understanding the Architecture

**Step 1: Core Concepts**
- Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - System design and module relationships
- Review [`CLAUDE.md`](CLAUDE.md) - Detailed development guidelines and patterns
- Check module dependency diagram below

**Step 2: Type System**
- GoPKI uses Go generics extensively for type safety
- Key type constraints defined in `keypair/keypair.go:50-150`
- All modules follow these type patterns - **review them first**

**Step 3: Format Support**
- PEM, DER, SSH, PKCS#12 formats all supported
- Format conversion logic in `format/` package
- See module-specific READMEs for conversion patterns

### Common Modification Patterns

**Adding New Algorithm Support:**
1. Read existing algorithm implementation in relevant `algo/` directory
2. Check test patterns in `*_algo_test.go`
3. Verify compatibility test requirements in `compatibility/`
4. Update format conversion functions
5. Add to documentation and examples

**Fixing Bugs:**
1. **Start with tests** - Read `*_test.go` files first to understand expected behavior
2. Check recent changes: `git log --oneline -10 <file>`
3. Review error handling patterns in similar functions
4. Run specific tests: `task test:specific -- TestName`
5. Verify compatibility: `task test:compatibility`

**Adding OpenSSL Compatibility:**
1. Read [`docs/OPENSSL_COMPAT.md`](docs/OPENSSL_COMPAT.md) for current status
2. Review `compatibility/helpers.go` for OpenSSL integration patterns
3. Add test in appropriate `compatibility/*/` directory
4. Update [`docs/COMPATIBILITY_REPORT.md`](docs/COMPATIBILITY_REPORT.md) with findings

### Code Reading Order for New AI Agents

**First Session (Core Understanding):**
```
1. README.md (this file) - Project overview
2. CLAUDE.md - Development guidelines
3. docs/ARCHITECTURE.md - System design
4. keypair/README.md - Foundation module
5. encryption/README.md - Most complex module
```

**For Specific Features:**
```
Certificate Operations:
  cert/README.md → cert/cert.go → cert/ca.go → examples/certificates/

Encryption:
  encryption/README.md → encryption/envelope/envelope.go →
  encryption/asymmetric/*.go → compatibility/encryption/

Signing:
  signing/README.md → signing/signer.go → signing/formats/pkcs7.go →
  examples/signing/
```

### Key Files Map

**Core Type Definitions:**
- `keypair/keypair.go:50-150` - Generic type constraints (START HERE)
- `encryption/types.go` - Encryption types
- `signing/types.go` - Signature types
- `cert/types.go` - Certificate types

**Main Implementations:**
- `keypair/manager.go` - Key pair management
- `encryption/envelope/envelope.go:150-450` - Envelope encryption
- `signing/signer.go:100-300` - Document signing
- `cert/ca.go:75-250` - Certificate authority operations

**Testing Infrastructure:**
- `compatibility/helpers.go` - OpenSSL integration utilities
- `*_test.go` - Unit tests (80.3% coverage)
- `examples/*/main.go` - Integration examples

### Project Conventions

**Type Safety:**
- No `any`/`interface{}` in core APIs (exceptions: metadata maps only)
- Use generic constraints from `keypair/keypair.go`
- Compile-time type checking enforced

**Security:**
- Minimum RSA key size: 2048 bits (enforced)
- File permissions: 0600 (private keys), 0700 (directories)
- No raw key material exposure in APIs

**Error Handling:**
- All functions return explicit errors (no panics)
- Errors wrapped with context: `fmt.Errorf("context: %w", err)`

**Testing:**
- Run tests before changes: `task test`
- Run specific tests: `task test:specific -- TestName`
- Check coverage: `task test:coverage`
- Verify compatibility: `task test:compatibility`

### Getting Help

**Documentation:**
- **[`docs/AI_NAVIGATION.md`](docs/AI_NAVIGATION.md)** - Comprehensive AI navigation guide ⭐
- Module-specific READMEs for detailed API docs
- `docs/` directory for conceptual guides (ARCHITECTURE, ALGORITHMS, OPENSSL_COMPAT)
- `examples/` directory for working code
- [`docs/COMPATIBILITY_REPORT.md`](docs/COMPATIBILITY_REPORT.md) for OpenSSL interoperability

**Code Exploration:**
- Use `task docs:serve` to browse godoc locally (http://localhost:6060)
- Check test files for usage examples
- Review git history for context: `git log -p <file>`

**When Stuck:**
- Understanding type system → Read `keypair/keypair.go:50-150` first
- Envelope encryption issues → See `encryption/README.md` AI Quick Start
- OpenSSL compatibility → Read `docs/OPENSSL_COMPAT.md`
- Module relationships → Read `docs/ARCHITECTURE.md`
- Algorithm selection → Read `docs/ALGORITHMS.md`

**Critical Resources for AI Agents:**
1. [`docs/AI_NAVIGATION.md`](docs/AI_NAVIGATION.md) - Navigation paths, bug patterns, troubleshooting
2. [`keypair/README.md`](keypair/README.md) - Foundation module with complete file map
3. [`encryption/README.md`](encryption/README.md) - Most complex module, detailed structure
4. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - System design and data flows
5. [`docs/OPENSSL_COMPAT.md`](docs/OPENSSL_COMPAT.md) - OpenSSL integration patterns

---

## 🏗️ Architecture

GoPKI is structured as **five core modules** with strong type relationships:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   keypair/      │◄───┤     cert/        │◄───┤   signing/      │
│ Core Key Mgmt   │    │ X.509 Certs      │    │ Digital Sigs    │
│ (75.3% coverage)│    │ (74.3% coverage) │    │ (79.8% coverage)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                        ▲                       ▲
         │                        │                       │
         └────────┬─────────────────────────────────────────┘
                  ▼                ▼
         ┌─────────────────┐    ┌──────────────────┐
         │  encryption/    │    │    pkcs12/       │
         │ Data Encryption │    │ PKCS#12 Files    │
         │ (89.1% coverage)│    │ (79.1% coverage) │
         └─────────────────┘    └──────────────────┘
```

**Module Documentation:**
- **[`keypair/README.md`](keypair/README.md)** - Foundation: Type-safe key generation and management
- **[`cert/README.md`](cert/README.md)** - X.509 certificates, CA operations, certificate chains
- **[`signing/README.md`](signing/README.md)** - Digital signatures, PKCS#7/CMS formats
- **[`encryption/README.md`](encryption/README.md)** - Multi-algorithm encryption, envelope encryption
- **[`pkcs12/README.md`](pkcs12/README.md)** - PKCS#12 file management and certificate bundling

**Detailed Architecture:** See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for complete system design

## 🚀 Quick Start

### Generate Key Pairs

```go
import (
    "crypto/rsa"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

// Generate RSA key pair with Manager (recommended)
manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)

// Save with secure permissions (0600 for private, 0644 for public)
manager.SaveToPEM("private.pem", "public.pem")

// Convert to different formats
privateSSH, publicSSH, _ := manager.ToSSH("user@host", "")
privateDER, publicDER, _ := manager.ToDER()
```

**See [`keypair/README.md`](keypair/README.md) for complete key management documentation**

### Create Certificates

```go
import (
    "crypto/x509/pkix"
    "time"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

// Generate key pair
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// Create self-signed certificate
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "example.com"},
    DNSNames: []string{"example.com", "www.example.com"},
    ValidFor: 365 * 24 * time.Hour,
})
```

**See [`cert/README.md`](cert/README.md) for CA operations and certificate chains**

### Sign Documents

```go
import (
    "github.com/jasoet/gopki/signing"
)

// Sign document with key pair and certificate
document := []byte("Important contract")
signature, _ := signing.SignDocument(document, keyPair, certificate)

// Verify signature
_ = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
```

**See [`signing/README.md`](signing/README.md) for PKCS#7/CMS signatures and advanced options**

### Encrypt Data

```go
import (
    "github.com/jasoet/gopki/encryption"
)

// Encrypt for certificate recipient
encrypted, _ := encryption.EncryptForCertificate(
    []byte("Secret message"),
    certificate.Certificate,
    encryption.DefaultEncryptOptions(),
)

// Decrypt with private key
decrypted, _ := encryption.DecryptWithKeyPair(encrypted, keyPair)
```

**See [`encryption/README.md`](encryption/README.md) for envelope encryption and multi-recipient support**

## 📚 Examples

Comprehensive examples with complete documentation:

```bash
# Install Task runner
go install github.com/go-task/task/v3/cmd/task@latest

# Run all examples
task examples:run

# Run specific examples
task examples:keypair      # Key generation and format conversion
task examples:certificates # CA hierarchies and certificate chains
task examples:signing      # Document signing with multiple algorithms
task examples:encryption   # Data encryption with various methods
```

**Example Documentation:**
- [`examples/keypair/doc.md`](examples/keypair/doc.md) - Key management examples
- [`examples/certificates/doc.md`](examples/certificates/doc.md) - Certificate examples
- [`examples/signing/doc.md`](examples/signing/doc.md) - Signing examples
- [`examples/encryption/doc.md`](examples/encryption/doc.md) - Encryption examples
- [`examples/pkcs12/doc.md`](examples/pkcs12/doc.md) - PKCS#12 bundle examples

## 🔢 Algorithm Support

| Algorithm | Key Sizes | Key Agreement | Signing | Encryption | Certificate |
|-----------|-----------|---------------|---------|------------|-------------|
| **RSA** | 2048/3072/4096 | ❌ | ✅ | ✅ | ✅ |
| **ECDSA** | P-224/256/384/521 | ✅ (ECDH) | ✅ | ✅ | ✅ |
| **Ed25519** | 256-bit | ✅ (X25519) | ✅ | ✅ (key-pair only) | ⚠️ |

**Format Support:** PEM, DER, SSH, PKCS#12 (all algorithms)

**See [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md) for detailed algorithm guide and decision trees**

## 🛡️ Security Features

**Cryptographic Security:**
- ✅ Enforced minimum key sizes (RSA ≥2048 bits)
- ✅ Secure random sources (`crypto/rand.Reader` only)
- ✅ Authenticated encryption (AES-GCM)
- ✅ Timing attack resistant (Ed25519)

**File System Security:**
- ✅ Secure permissions (0600 for private keys, 0700 for directories)
- ✅ Atomic file operations
- ✅ Secure temporary file cleanup

**Memory Security:**
- ✅ Type-safe APIs with generic constraints
- ✅ No raw cryptographic material exposure
- ✅ Defensive copying of sensitive parameters

## 🧪 Testing

**Test Coverage:** 80.3% across 844+ tests

```bash
# Run comprehensive test suite
task test              # Full suite with race detection
task test:coverage     # Generate HTML coverage report
task test:compatibility # OpenSSL/OpenSSH compatibility tests

# Code quality
task lint:full         # Comprehensive linting
task lint:security     # Security-focused linting (gosec)
task format:check      # Verify code formatting
```

**Module Coverage:**
- encryption/ 89.1% (highest)
- keypair/algo/ 87.8%
- signing/ 79.8%
- pkcs12/ 79.1%
- cert/ 74.3%
- keypair/ 75.3%

## 🤝 Compatibility

**OpenSSL Compatibility: 95%+**
- ✅ Certificate management (100%)
- ✅ Digital signatures (95% - Ed25519 PKCS#7 has expected limitations)
- ✅ Key agreement (100% - ECDH, X25519)
- ⚠️ RSA-OAEP encryption (parameter differences)

**OpenSSH Compatibility: 100%**
- ✅ SSH key format validation (all algorithms)
- ✅ SSH fingerprint generation
- ✅ authorized_keys format support

**Compatibility Report:** See [`docs/COMPATIBILITY_REPORT.md`](docs/COMPATIBILITY_REPORT.md) for detailed interoperability testing results

**OpenSSL Integration Guide:** See [`docs/OPENSSL_COMPAT.md`](docs/OPENSSL_COMPAT.md) for integration patterns

## 📖 Standards Compliance

- **RFC 5652** - Cryptographic Message Syntax (CMS)
- **RFC 5280** - X.509 Public Key Infrastructure
- **RFC 3447** - PKCS #1: RSA Cryptography
- **RFC 7748** - Elliptic Curves (Ed25519, X25519)
- **RFC 5208** - PKCS #8: Private-Key Information
- **PKCS #7** - Cryptographic Message Syntax
- **PKCS #12** - Personal Information Exchange
- **OpenSSH** - SSH public/private key formats

## 💻 Development

**Using Taskfile (Recommended):**
```bash
task setup             # Initialize project
task test              # Run tests
task format            # Format code
task lint:full         # Comprehensive linting
task examples:run      # Run all examples
task clean             # Clean build artifacts
```

**Manual Commands:**
```bash
go test ./... -race -coverprofile=coverage.out
go build ./...
go fmt ./...
go vet ./...
```

**Development Guide:** See [`CLAUDE.md`](CLAUDE.md) for comprehensive development documentation

## 🔗 Dependencies

Minimal, carefully selected dependencies:
- **go.mozilla.org/pkcs7** v0.9.0 - Battle-tested CMS/PKCS#7
- **golang.org/x/crypto** v0.42.0 - Extended cryptographic primitives
- **software.sslmate.com/src/go-pkcs12** v0.6.0 - Standards-compliant PKCS#12

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- **Mozilla** for the excellent PKCS#7 library
- **Go Team** for outstanding cryptographic standard library
- **Community** for feedback and contributions

## 📞 Support

- **Documentation**: Module-specific READMEs, examples, and guides
- **Issues**: [GitHub Issues](https://github.com/jasoet/gopki/issues)
- **Questions**: Use GitHub Issues for questions and feature requests

---

**Made with ❤️ in Go | Type-Safe Cryptography for Production**