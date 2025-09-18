# GoPKI

[![Go Version](https://img.shields.io/badge/Go-1.24.5+-blue.svg)](https://golang.org)
[![Test Coverage](https://img.shields.io/badge/Coverage-80.3%25-green.svg)](https://github.com/jasoet/gopki)
[![Go Report Card](https://goreportcard.com/badge/github.com/jasoet/gopki)](https://goreportcard.com/report/github.com/jasoet/gopki)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **production-ready Go library for PKI (Public Key Infrastructure) operations** that emphasizes **type-safe cryptography through Go generics**. GoPKI provides comprehensive cryptographic functionality with 80.3% test coverage across 844+ tests and strict type safety throughout all APIs.

## 🚀 Key Features

- **🔒 Type-Safe Cryptography**: Go generics eliminate `any`/`interface{}` types in core APIs
- **🛡️ Security-First Design**: Enforced minimum key sizes, secure file permissions, cryptographic best practices
- **📜 Standards Compliant**: Full support for X.509, PKCS#7/CMS, PKCS#12, SSH formats
- **🧪 Production Ready**: 80.3% test coverage, comprehensive CI/CD pipeline, semantic versioning
- **⚡ High Performance**: Zero runtime overhead from generics, optimized algorithms
- **🔧 Developer Friendly**: Comprehensive Taskfile, extensive examples, excellent documentation

## 📦 Installation

```bash
go get github.com/jasoet/gopki
```

**Requirements**: Go 1.24.5 or later

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

## 🚀 Quick Start

### Generate RSA Key Pairs

```go
package main

import (
    "fmt"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA key pair with compile-time type safety
    keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Generated %d-bit RSA key pair\n", keyPair.PrivateKey.Size()*8)
}
```

### Create Self-Signed Certificate

```go
package main

import (
    "crypto/x509/pkix"
    "fmt"
    "time"

    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate key pair
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // Create certificate
    certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "example.com",
            Organization: []string{"My Organization"},
            Country:      []string{"US"},
        },
        DNSNames: []string{"example.com", "www.example.com"},
        ValidFor: 365 * 24 * time.Hour, // 1 year
    })

    if err != nil {
        panic(err)
    }

    fmt.Printf("Created certificate for: %s\n", certificate.Certificate.Subject.CommonName)
}
```

### Sign Documents

```go
package main

import (
    "fmt"

    "github.com/jasoet/gopki/signing"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/cert"
)

func main() {
    // Setup key pair and certificate
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
    certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Document Signer"},
        ValidFor: 365 * 24 * time.Hour,
    })

    // Sign document
    document := []byte("Important contract")
    signature, err := signing.SignDocument(document, keyPair, certificate)
    if err != nil {
        panic(err)
    }

    // Verify signature
    err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
    if err != nil {
        panic(err)
    }

    fmt.Println("Document signed and verified successfully!")
}
```

### Encrypt Data

```go
package main

import (
    "fmt"

    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/cert"
)

func main() {
    // Setup recipient
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
    certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Recipient"},
        ValidFor: 365 * 24 * time.Hour,
    })

    // Encrypt data
    data := []byte("Secret message")
    encrypted, err := encryption.EncryptForCertificate(data, certificate.Certificate,
        encryption.DefaultEncryptOptions())
    if err != nil {
        panic(err)
    }

    // Decrypt data
    decrypted, err := encryption.DecryptWithKeyPair(encrypted, keyPair)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Original: %s\n", data)
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## 📚 Comprehensive Examples

GoPKI includes extensive examples demonstrating all features:

```bash
# Install Task runner (recommended)
go install github.com/go-task/task/v3/cmd/task@latest

# Run all examples
task examples:run

# Run specific examples
task examples:keypair      # Key generation and format conversion
task examples:certificates # CA hierarchies and certificate chains
task examples:signing      # Document signing with multiple algorithms
task examples:encryption   # Data encryption with various methods
```

## 🔧 Core Modules

### 1. **keypair/** - Foundation Module

**Type-safe key generation and management**

```go
// Supported algorithms with compile-time safety
rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)       // RSA 2048/3072/4096-bit
ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)         // ECDSA P-224/256/384/521
ed25519Keys, _ := algo.GenerateEd25519KeyPair()              // Ed25519

// Format conversions with type safety
keypair.ToPEMFiles(rsaKeys, "private.pem", "public.pem")     // PEM format
keypair.ToDERFiles(rsaKeys, "private.der", "public.der")     // DER format
keypair.ToSSHFiles(rsaKeys, "id_rsa", "id_rsa.pub", "user@example.com", "")  // SSH format
```

**Security Features:**
- ✅ Enforced minimum RSA key sizes (≥2048 bits)
- ✅ Secure file permissions (0600 for private keys)
- ✅ Memory-safe key handling
- ✅ Format validation and type safety

### 2. **cert/** - X.509 Certificate Management

**Certificate creation, CA operations, and chain management**

```go
// Create CA certificate
caCert, _ := cert.CreateCACertificate(caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "My Root CA"},
    ValidFor: 10 * 365 * 24 * time.Hour,
    IsCA: true,
    MaxPathLen: 2,  // Path length constraint
})

// Sign server certificate with CA
serverCert, _ := cert.SignCertificate(caCert, caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "server.example.com"},
    DNSNames: []string{"server.example.com", "api.example.com"},
    IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
    ValidFor: 365 * 24 * time.Hour,
}, serverKeys.PublicKey)

// Verify certificate chain
err := cert.VerifyCertificate(serverCert, caCert)
```

**CA Features:**
- ✅ Path length constraints for intermediate CAs
- ✅ Subject Alternative Names (DNS, IP, Email)
- ✅ Certificate chain verification
- ✅ BasicConstraints and KeyUsage extensions

### 3. **signing/** - Digital Signatures

**Document signing with multiple formats and algorithms**

```go
// Advanced signing with options
signature, _ := signing.SignData(document, keyPair, certificate, signing.SignOptions{
    HashAlgorithm:      crypto.SHA256,
    Format:             signing.FormatPKCS7Detached,
    IncludeCertificate: true,
    IncludeChain:       true,
    TimestampURL:       "http://timestamp.example.com",
})

// PKCS#7/CMS format support
pkcs7Data, _ := signing.CreatePKCS7Signature(document, keyPair, certificate, true)
info, _ := signing.VerifyPKCS7Signature(document, pkcs7Data)
```

**Signature Formats:**
- ✅ Raw signatures (smallest size)
- ✅ PKCS#7 attached (signature + document)
- ✅ PKCS#7 detached (signature only, recommended)
- ✅ Certificate chain inclusion
- ✅ RFC 3161 timestamp support

### 4. **encryption/** - Data Encryption

**Type-safe encryption with multiple algorithms and CMS support**

```go
// Multiple encryption algorithms
rsaEncrypted, _ := encryption.EncryptRSA(smallData, publicKey)           // RSA-OAEP (≤190 bytes)
ecdhEncrypted, _ := encryption.EncryptECDH(largeData, ecdsaPublicKey)   // ECDH + AES-GCM
x25519Encrypted, _ := encryption.EncryptX25519(largeData, ed25519Key)   // X25519 + AES-GCM

// Envelope encryption for large data/multiple recipients
envelope, _ := encryption.CreateEnvelope(largeData, []*x509.Certificate{cert1, cert2, cert3})
cmsData, _ := encryption.EncodeToCMS(envelope)  // Standards-compliant CMS format

// Type-safe decryption
decrypted, _ := encryption.DecodeFromCMS(cmsData, recipientCert, privateKey)
```

**Encryption Features:**
- ✅ Multiple algorithms (RSA-OAEP, ECDH+AES-GCM, X25519+AES-GCM)
- ✅ Envelope encryption for large data
- ✅ Multi-recipient support
- ✅ CMS (RFC 5652) format compliance
- ✅ Type-safe APIs with generic constraints

## 🔢 Algorithm Feature Matrix

| **Encryption Operation** | **RSA** | **ECDSA** | **Ed25519** | **Notes** |
|---------------------------|---------|-----------|-------------|-----------|
| **Direct Data Encryption** | ✅ | ✅ | ✅ | All algorithms supported for key-pair encryption |
| **Public Key Only Encryption** | ✅ | ✅ | ❌ | Ed25519 requires full key pair due to key derivation limitations |
| **Certificate-Based Encryption** | ✅ | ✅ | ❌ | Ed25519 limited by public-key-only requirement |
| **Envelope Large Data** | ✅ | ✅ | ✅* | Ed25519 works with key pairs, not with certificates |
| **CMS Format Support** | ✅ | ✅ | ✅* | Ed25519 limited to key-pair workflows |

**Legend:**
- ✅ **Full Support**: Complete implementation with all features
- ❌ **Not Supported**: Technical limitations prevent implementation
- ✅* **Partial Support**: Works with restrictions (see notes)

**Ed25519 Limitations:**
- **Root Cause**: Key derivation incompatibility between Ed25519→X25519 public key conversion (RFC 7748) and Ed25519→X25519 private key conversion (Go standard method)
- **Impact**: Public-key-only encryption fails, requiring full key pair for encryption operations
- **Workaround**: Use `EncryptWithEd25519()` with complete key pairs instead of certificate-based encryption
- **Certificate Encryption**: Not supported - returns clear error with guidance to use RSA or ECDSA for certificate-based workflows

**Algorithm Recommendations:**
- **RSA**: Best for certificate-based encryption, maximum compatibility
- **ECDSA**: Modern choice with smaller keys and full feature support
- **Ed25519**: High performance signing, limited to key-pair encryption workflows

### 5. **pkcs12/** - PKCS#12 File Management

**Complete PKI material bundling and storage**

```go
// Create PKCS#12 file with certificate chain
err := pkcs12.CreateP12File("certificate.p12", privateKey, certificate,
    []*x509.Certificate{intermediateCert, rootCert}, pkcs12.CreateOptions{
        Password: "secure123",
        FriendlyName: "My Certificate",
        Iterations: 4096,  // Security vs performance
    })

// Load PKCS#12 file
container, _ := pkcs12.LoadFromP12File("certificate.p12", pkcs12.LoadOptions{
    Password: "secure123",
    TrustedCerts: []*x509.Certificate{rootCert},
})

// Quick operations
container, _ := pkcs12.QuickLoadP12("certificate.p12", "secure123")
```

## 🔄 Format Support Matrix

| Format | RSA | ECDSA | Ed25519 | Usage |
|--------|-----|-------|---------|-------|
| **PEM** | ✅ | ✅ | ✅ | Text-based, Base64 encoded, most common |
| **DER** | ✅ | ✅ | ✅ | Binary format, ~30% smaller than PEM |
| **SSH** | ✅ | ✅ | ✅ | OpenSSH format for authorized_keys |
| **PKCS#12** | ✅ | ✅ | ✅ | Password-protected container format |

## 🛡️ Security Features

### Cryptographic Security
- **Strong Random Sources**: Uses `crypto/rand.Reader` exclusively
- **Minimum Key Sizes**: RSA ≥2048 bits enforced at compile time
- **Secure Algorithms**: Only NIST curves and Ed25519 supported
- **Authenticated Encryption**: AES-GCM prevents tampering
- **Timing Attack Resistance**: Ed25519 and constant-time implementations

### File System Security
- **Secure Permissions**: Private keys saved with 0600 permissions
- **Directory Security**: Created with 0700 permissions (owner-only access)
- **Atomic Operations**: Prevent partial writes and race conditions
- **Secure Cleanup**: Temporary files properly removed

### Memory Security
- **Type Safety**: Generic constraints prevent runtime type errors
- **No Raw Material Exposure**: Cryptographic keys wrapped in safe types
- **Defensive Copying**: Sensitive parameters copied defensively
- **Validated Parameters**: All inputs validated before cryptographic operations

## 🧪 Testing and Quality Assurance

### Test Coverage Statistics
- **Overall Coverage**: 80.3%
- **Total Tests**: 844+ individual tests across 23 test files
- **Test Categories**: Unit, Integration, Security, Benchmark, Edge Case

**Module Coverage:**
```
encryption/          89.1% (highest - most complex module)
keypair/algo/        87.8% (algorithm implementations)
signing/             79.8% (core signing)
pkcs12/              79.1% (PKCS#12 operations)
cert/                74.3% (certificate operations)
keypair/             75.3% (manager and utilities)
```

### Quality Assurance Tools
```bash
# Run comprehensive test suite
task test              # Full test suite with race detection
task test:coverage     # Generate HTML coverage report

# Code quality checks
task lint:full         # Comprehensive linting with golangci-lint
task lint:security     # Security-focused linting (gosec)
task format:check      # Verify code formatting

# Security scanning
task security:check    # Dependency vulnerability scanning
```

## 📖 Standards Compliance

GoPKI implements and adheres to industry standards:

- **RFC 5652**: Cryptographic Message Syntax (CMS)
- **RFC 3447**: PKCS #1: RSA Cryptography Specifications
- **RFC 5208**: PKCS #8: Private-Key Information Syntax
- **RFC 7748**: Elliptic Curves for Security (Ed25519, X25519)
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate
- **PKCS #7**: Cryptographic Message Syntax Standard
- **PKCS #12**: Personal Information Exchange Syntax Standard
- **OpenSSH**: SSH public/private key formats

## 🔗 Dependencies

GoPKI uses minimal, carefully selected dependencies:

- **go.mozilla.org/pkcs7** v0.9.0 - Battle-tested CMS/PKCS#7 implementation
- **golang.org/x/crypto** v0.42.0 - Extended cryptographic primitives
- **software.sslmate.com/src/go-pkcs12** v0.6.0 - Standards-compliant PKCS#12

**Design Philosophy**: Minimal dependencies, security-focused, standards-compliant, battle-tested libraries.

## 💻 Development

### Using Taskfile (Recommended)

Install [Task](https://taskfile.dev/installation/) for streamlined development:

```bash
# Setup
task setup             # Initialize project and dependencies
task                   # Show all available tasks

# Development workflow
task test              # Run tests with coverage (80.3%)
task format            # Format code
task lint:full         # Comprehensive linting
task examples:run      # Run all examples

# Building
task build             # Build library
task build:examples    # Build example binaries

# Cleanup
task clean             # Clean build artifacts
task examples:clean    # Clean example outputs
```

### Manual Development

```bash
# Core operations
go test ./... -race -coverprofile=coverage.out
go build ./...
go fmt ./...
go vet ./...

# Examples (with build tags)
go run -tags example ./examples/keypair/main.go
go run -tags example ./examples/certificates/main.go
go run -tags example ./examples/signing/main.go
go run -tags example ./examples/encryption/main.go
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Write** tests for new functionality
4. **Ensure** all tests pass (`task test`)
5. **Format** code (`task format`)
6. **Lint** code (`task lint:full`)
7. **Commit** changes (`git commit -m 'Add amazing feature'`)
8. **Push** to branch (`git push origin feature/amazing-feature`)
9. **Open** a Pull Request

### Development Guidelines

- **Type Safety First**: Use generic constraints, avoid `any`/`interface{}`
- **Security Focus**: Follow established security practices
- **Test Coverage**: Maintain or improve 80.3% coverage
- **Documentation**: Update examples and docs for API changes
- **Standards Compliance**: Adhere to cryptographic standards

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Mozilla** for the excellent PKCS#7 library
- **Go Team** for outstanding cryptographic standard library
- **Community** for feedback and contributions

## 📞 Support

- **Documentation**: Comprehensive examples and API docs included
- **Issues**: [GitHub Issues](https://github.com/jasoet/gopki/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jasoet/gopki/discussions)

## 🗂️ Project Structure

```
gopki/
├── keypair/           # Core key management (foundation)
│   ├── algo/          # Algorithm implementations (RSA, ECDSA, Ed25519)
│   └── format/        # Format definitions (PEM, DER, SSH)
├── cert/              # X.509 certificate operations
├── signing/           # Document signing and verification
│   └── formats/       # PKCS#7/CMS format support
├── encryption/        # Data encryption and decryption
│   ├── asymmetric/    # Asymmetric encryption algorithms
│   ├── symmetric/     # Symmetric encryption (AES-GCM)
│   ├── envelope/      # Envelope encryption
│   └── certificate/   # Certificate-based encryption
├── pkcs12/           # PKCS#12 file management
├── examples/         # Comprehensive usage examples
│   ├── keypair/      # Key generation examples
│   ├── certificates/ # Certificate creation examples
│   ├── signing/      # Document signing examples
│   └── encryption/   # Data encryption examples
└── docs/             # Additional documentation
```

## 🚀 Production Usage

GoPKI is production-ready with:

- ✅ **80.3% Test Coverage** with 844+ tests
- ✅ **Type-Safe APIs** with Go generics
- ✅ **Security Best Practices** enforced throughout
- ✅ **Standards Compliance** for interoperability
- ✅ **Comprehensive Examples** for all use cases
- ✅ **CI/CD Pipeline** with automated testing
- ✅ **Semantic Versioning** for reliable releases
- ✅ **Minimal Dependencies** for security and maintenance

Perfect for applications requiring robust PKI operations, certificate management, document signing, and data encryption with strong type safety guarantees.

---

**Made with ❤️ in Go | Type-Safe Cryptography for Production**