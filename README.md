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

## 📑 Table of Contents

- [🚀 Key Features](#-key-features)
- [📦 Installation](#-installation)
- [🏗️ Architecture](#-architecture)
- [🚀 Quick Start](#-quick-start)
  - [Generate RSA Key Pairs](#generate-rsa-key-pairs)
  - [Create Self-Signed Certificate](#create-self-signed-certificate)
  - [Sign Documents](#sign-documents)
  - [Encrypt Data](#encrypt-data)
- [📚 Comprehensive Examples](#-comprehensive-examples)
- [🔧 Core Modules](#-core-modules)
  - [1. keypair/ - Foundation Module](#1-keypair---foundation-module)
  - [2. cert/ - X.509 Certificate Management](#2-cert---x509-certificate-management)
  - [3. signing/ - Digital Signatures](#3-signing---digital-signatures)
  - [4. encryption/ - Data Encryption](#4-encryption---data-encryption)
  - [5. pkcs12/ - PKCS#12 File Management](#5-pkcs12---pkcs12-file-management)
- [🔢 Algorithm Feature Matrix](#-algorithm-feature-matrix)
- [🔄 Format Support Matrix](#-format-support-matrix)
- [🛡️ Security Features](#-security-features)
- [🧪 Testing and Quality Assurance](#-testing-and-quality-assurance)
- [📖 Standards Compliance](#-standards-compliance)
- [🔗 Dependencies](#-dependencies)
- [💻 Development](#-development)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Support](#-support)
- [🗂️ Project Structure](#-project-structure)
- [🚀 Production Usage](#-production-usage)

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
    "crypto/rsa"
    "fmt"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Method 1: Direct key generation
    keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Generated %d-bit RSA key pair\n", keyPair.PrivateKey.Size()*8)

    // Method 2: Using KeyPair Manager (Recommended)
    manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
    if err != nil {
        panic(err)
    }

    // Extract keys with type safety
    privateKey := manager.PrivateKey()
    publicKey := manager.PublicKey()

    // Convert to PEM format
    privatePEM, publicPEM, err := manager.ToPEM()
    if err != nil {
        panic(err)
    }

    // Save to files with secure permissions
    err = manager.SaveToPEM("private.pem", "public.pem")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Generated and saved %d-bit RSA key pair\n", privateKey.Size()*8)
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

GoPKI includes extensive examples demonstrating all features with complete source code, documentation, and test files:

### 🔧 Running Examples

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

### 📂 Example Files & Documentation

| **Module** | **Source Code** | **Documentation** | **Key Test Files** |
|------------|-----------------|-------------------|-------------------|
| **Key Management** | [`examples/keypair/main.go`](examples/keypair/main.go) | [`examples/keypair/doc.md`](examples/keypair/doc.md) | [`keypair/algo/*_test.go`](keypair/algo/) |
| **Certificates** | [`examples/certificates/main.go`](examples/certificates/main.go) | [`examples/certificates/doc.md`](examples/certificates/doc.md) | [`cert/cert_test.go`](cert/cert_test.go) |
| **Digital Signing** | [`examples/signing/main.go`](examples/signing/main.go) | [`examples/signing/doc.md`](examples/signing/doc.md) | [`signing/signing_test.go`](signing/signing_test.go) |
| **Data Encryption** | [`examples/encryption/main.go`](examples/encryption/main.go) | [`examples/encryption/doc.md`](examples/encryption/doc.md) | [`encryption/*/test.go`](encryption/) |
| **PKCS#12 Bundles** | [`examples/pkcs12/main.go`](examples/pkcs12/main.go) | [`examples/pkcs12/doc.md`](examples/pkcs12/doc.md) | [`pkcs12/pkcs12_test.go`](pkcs12/pkcs12_test.go) |

### 🎯 Example Features by Module

**🔐 Key Management Examples** ([`examples/keypair/`](examples/keypair/))
- **KeyPair Manager**: Unified interface for all algorithms with type safety
- RSA, ECDSA, Ed25519 key generation with compile-time type constraints
- PEM/DER/SSH format conversions with automatic format detection
- File operations with secure permissions (0600 for private keys, 0700 for directories)
- Key validation, comparison, and metadata extraction
- Loading existing keys from various formats into Manager
- Cross-algorithm compatibility testing and benchmarking

**📜 Certificate Examples** ([`examples/certificates/`](examples/certificates/))
- Self-signed certificate creation
- CA certificate hierarchies with path length constraints
- Intermediate CA signing workflows
- Certificate chain verification
- Subject Alternative Names (DNS, IP, Email)

**✍️ Signing Examples** ([`examples/signing/`](examples/signing/))
- Multi-algorithm document signing (RSA, ECDSA, Ed25519)
- PKCS#7/CMS format support (attached/detached)
- Certificate chain inclusion in signatures
- Signature verification with certificate validation
- Performance benchmarking across algorithms

**🔒 Encryption Examples** ([`examples/encryption/`](examples/encryption/))
- Multi-algorithm encryption (RSA-OAEP, ECDH+AES-GCM, X25519+AES-GCM)
- Envelope encryption for large data sets
- Multi-recipient encryption workflows
- Certificate-based encryption with PKI integration
- CMS format compliance (RFC 5652)
- Performance analysis and file-based operations

**📦 PKCS#12 Bundle Examples** ([`examples/pkcs12/`](examples/pkcs12/))
- **Multi-Algorithm P12 Creation**: RSA, ECDSA, Ed25519 certificate bundles
- **Certificate Chain Bundling**: Complete CA hierarchies in P12 format
- **Real-World Scenarios**: Web server, client auth, code signing certificates
- **Security Options**: Password protection, custom iterations, friendly names
- **Cross-Platform Migration**: Import/export workflows for different systems
- **Integration Workflows**: Seamless integration with keypair Manager and cert modules
- **Validation & Security**: Container validation and security best practices

## 🔧 Core Modules

### 1. **keypair/** - Foundation Module

**Type-safe key generation and management with KeyPair Manager**

```go
// Method 1: Direct algorithm usage
rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)       // RSA 2048/3072/4096-bit
ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)         // ECDSA P-224/256/384/521
ed25519Keys, _ := algo.GenerateEd25519KeyPair()              // Ed25519

// Method 2: KeyPair Manager (Recommended) - provides unified interface
import "crypto/rsa"
import "crypto/ecdsa"
import "crypto/ed25519"

// Generate with Manager
rsaManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
ecdsaManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
ed25519Manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")

// Extract keys with type safety
privateKey := rsaManager.PrivateKey()
publicKey := rsaManager.PublicKey()

// Unified format conversions with Manager
privatePEM, publicPEM, _ := rsaManager.ToPEM()              // PEM format
privateDER, publicDER, _ := rsaManager.ToDER()              // DER format
privateSSH, publicSSH, _ := rsaManager.ToSSH("user@host", "") // SSH format

// Unified file operations with secure permissions
rsaManager.SaveToPEM("private.pem", "public.pem")           // Save PEM files
rsaManager.SaveToDER("private.der", "public.der")           // Save DER files
rsaManager.SaveToSSH("id_rsa", "id_rsa.pub", "user@host", "") // Save SSH files

// Load existing keys into Manager
loadedManager, _ := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("private.pem")

// Validation and key information
info, _ := rsaManager.GetInfo()                             // Get algorithm metadata
err := rsaManager.Validate()                               // Validate key pair integrity
isValid := rsaManager.IsValid()                            // Check manager state
```

**KeyPair Manager Benefits:**
- ✅ **Unified Interface**: Same API across RSA, ECDSA, and Ed25519 algorithms
- ✅ **Type Safety**: Generic constraints prevent runtime type errors
- ✅ **Format Agnostic**: Automatic conversion between PEM/DER/SSH formats
- ✅ **Secure File I/O**: Built-in secure permissions (0600/0700) and atomic operations
- ✅ **Validation**: Comprehensive key pair integrity and security validation
- ✅ **Metadata**: Algorithm detection and key information extraction
- ✅ **Loading**: Support for loading existing keys from any format into Manager

**Security Features:**
- ✅ Enforced minimum RSA key sizes (≥2048 bits)
- ✅ Secure file permissions (0600 for private keys, 0700 for directories)
- ✅ Memory-safe key handling with zero runtime overhead
- ✅ Format validation and compile-time type safety

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

**Complete PKI material bundling and storage with RFC 7292 compliance**

```go
// Method 1: Quick P12 creation for simple use cases
err := pkcs12.QuickCreateP12("basic.p12", "password123", privateKey, certificate)

// Method 2: Advanced P12 creation with full control
opts := pkcs12.CreateOptions{
    Password:     "secure_password_2024",
    FriendlyName: "Production Web Server Certificate",
    Iterations:   8192, // High security iterations
}
err := pkcs12.CreateP12File("webserver.p12", serverKey, serverCert,
    []*x509.Certificate{intermediateCert, rootCert}, opts)

// Integration with KeyPair Manager
manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
err := pkcs12.QuickCreateP12("from_manager.p12", "password", manager.PrivateKey(), certificate)

// Loading and validation
container, _ := pkcs12.LoadFromP12File("certificate.p12", pkcs12.LoadOptions{
    Password: "secure123",
    TrustedCerts: []*x509.Certificate{rootCert},
})

// Container operations
keyType := container.GetKeyType()                    // "RSA", "ECDSA", "Ed25519"
chain := container.ExtractCertificateChain()        // Get full certificate chain
err := container.Validate()                         // Validate container integrity

// Quick loading for simple cases
container, _ := pkcs12.QuickLoadP12("certificate.p12", "secure123")

// Real-world scenarios
// Web server certificate bundle
pkcs12.CreateP12File("webserver.p12", serverKey, serverCert, caChain, webServerOpts)

// Client authentication certificate
pkcs12.QuickCreateP12("client_auth.p12", "client_password", clientKey, clientCert)

// Code signing certificate with maximum security
pkcs12.CreateP12File("codesign.p12", codeSignKey, codeSignCert, nil,
    pkcs12.CreateOptions{
        Password: "code_sign_password",
        FriendlyName: "Software Publisher Certificate",
        Iterations: 16384, // Maximum security for code signing
    })
```

**PKCS#12 Features:**
- ✅ **Multi-Algorithm Support**: RSA, ECDSA, Ed25519 private keys
- ✅ **Certificate Chains**: Bundle complete CA hierarchies
- ✅ **Password Protection**: Configurable iteration counts for security
- ✅ **Cross-Platform**: Compatible with Windows, macOS, Linux
- ✅ **Integration**: Seamless with keypair Manager and cert modules
- ✅ **Validation**: Container integrity and certificate verification
- ✅ **Real-World Ready**: Web server, client auth, code signing use cases

**Security Levels:**
- **Development**: 2048 iterations
- **Production**: 4096-8192 iterations
- **High Security**: 16384+ iterations for sensitive applications

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

### 📋 Core Test Files

| **Module** | **Test Coverage** | **Key Test Files** | **Purpose** |
|------------|-------------------|-------------------|-------------|
| **keypair/** | 75.3% | [`keypair/algo/rsa_test.go`](keypair/algo/rsa_test.go)<br>[`keypair/algo/ecdsa_test.go`](keypair/algo/ecdsa_test.go)<br>[`keypair/algo/ed25519_test.go`](keypair/algo/ed25519_test.go) | Algorithm implementations, key generation, format conversion |
| **cert/** | 74.3% | [`cert/cert_test.go`](cert/cert_test.go)<br>[`cert/ca_test.go`](cert/ca_test.go) | Certificate creation, CA operations, chain verification |
| **signing/** | 79.8% | [`signing/signing_test.go`](signing/signing_test.go)<br>[`signing/formats/pkcs7_test.go`](signing/formats/pkcs7_test.go) | Document signing, PKCS#7/CMS formats, verification |
| **encryption/** | 89.1% | [`encryption/asymmetric/asymmetric_test.go`](encryption/asymmetric/asymmetric_test.go)<br>[`encryption/envelope/envelope_test.go`](encryption/envelope/envelope_test.go)<br>[`encryption/certificate/certificate_test.go`](encryption/certificate/certificate_test.go) | Multi-algorithm encryption, envelope encryption, certificate-based workflows |
| **pkcs12/** | 79.1% | [`pkcs12/pkcs12_test.go`](pkcs12/pkcs12_test.go) | PKCS#12 file operations, password protection, certificate bundling |

### 📖 Developer Documentation

- **[`CLAUDE.md`](CLAUDE.md)** - Development commands, architecture overview, and coding patterns for Claude Code AI
- **[`CHANGELOG.md`](CHANGELOG.md)** - Version history and release notes
- **[`examples/*/doc.md`](examples/)** - Detailed documentation for each example module

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
- **Questions**: Use GitHub Issues for questions and feature requests

## 🗂️ Project Structure

```
gopki/
├── keypair/                    # Core key management (foundation) - 75.3% coverage
│   ├── algo/                   # Algorithm implementations (RSA, ECDSA, Ed25519)
│   │   ├── rsa.go             # RSA key operations
│   │   ├── ecdsa.go           # ECDSA operations
│   │   ├── ed25519.go         # Ed25519 operations
│   │   ├── rsa_test.go        # RSA algorithm tests
│   │   ├── ecdsa_test.go      # ECDSA algorithm tests
│   │   └── ed25519_test.go    # Ed25519 algorithm tests
│   └── format/                # Format definitions (PEM, DER, SSH)
├── cert/                      # X.509 certificate operations - 74.3% coverage
│   ├── cert.go               # Certificate creation and management
│   ├── ca.go                 # Certificate Authority operations
│   ├── cert_test.go          # Certificate operation tests
│   └── ca_test.go            # CA operation tests
├── signing/                   # Document signing and verification - 79.8% coverage
│   ├── signing.go            # Core signing functionality
│   ├── formats/              # PKCS#7/CMS format support
│   │   └── pkcs7_test.go     # PKCS#7 format tests
│   └── signing_test.go       # Document signing tests
├── encryption/                # Data encryption and decryption - 89.1% coverage
│   ├── asymmetric/           # Asymmetric encryption algorithms
│   │   ├── asymmetric.go     # Core asymmetric operations
│   │   ├── rsa_test.go       # RSA encryption tests
│   │   ├── ecdsa_test.go     # ECDSA encryption tests
│   │   ├── ed25519_test.go   # Ed25519 encryption tests
│   │   └── asymmetric_test.go # Integration tests
│   ├── symmetric/            # Symmetric encryption (AES-GCM)
│   │   └── symmetric_test.go # AES-GCM tests
│   ├── envelope/             # Envelope encryption
│   │   └── envelope_test.go  # Envelope encryption tests
│   ├── certificate/          # Certificate-based encryption
│   │   └── certificate_test.go # Certificate encryption tests
│   ├── encryption_test.go    # Core encryption tests
│   └── cms_test.go          # CMS format tests
├── pkcs12/                   # PKCS#12 file management - 79.1% coverage
│   └── pkcs12_test.go       # PKCS#12 operation tests
├── examples/                 # Comprehensive usage examples with documentation
│   ├── keypair/             # Key generation examples
│   │   ├── main.go          # Key generation demonstration
│   │   └── doc.md           # Key management documentation
│   ├── certificates/        # Certificate creation examples
│   │   ├── main.go          # Certificate creation demonstration
│   │   └── doc.md           # Certificate management documentation
│   ├── signing/             # Document signing examples
│   │   ├── main.go          # Document signing demonstration
│   │   └── doc.md           # Digital signing documentation
│   ├── encryption/          # Data encryption examples
│   │   ├── main.go          # Encryption demonstration
│   │   └── doc.md           # Encryption documentation
│   └── pkcs12/              # PKCS#12 bundle examples
│       ├── main.go          # PKCS#12 demonstration
│       ├── doc.md           # PKCS#12 documentation
│       └── output/          # Generated P12 files (gitignored)
├── CLAUDE.md                # Development guide for Claude Code AI
├── CHANGELOG.md             # Version history and release notes
└── README.md               # This comprehensive guide
```

### 📊 Coverage Summary by Module
- **encryption/**: 89.1% (highest - most complex cryptographic operations)
- **signing/**: 79.8% (document signing and PKCS#7/CMS formats)
- **pkcs12/**: 79.1% (PKCS#12 file operations and bundling)
- **keypair/**: 75.3% (foundational key management operations)
- **cert/**: 74.3% (X.509 certificate operations and CA workflows)
- **Overall**: 79.9% across 844+ individual tests

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