# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Using Taskfile (Recommended)

The project includes a comprehensive Taskfile for streamlined development. Install Task from https://taskfile.dev/installation/

```bash
# Setup and Dependencies
task setup             # Initial project setup
task                   # Show all available tasks

# Testing
task test              # Run all tests with race detection
task test:verbose      # Verbose test output
task test:coverage     # Generate coverage report
task test:keypair      # Test keypair module
task test:cert         # Test certificate module
task test:format       # Test format module
task test:encryption   # Test encryption module
task test:specific -- TestName  # Run specific test

# Code Quality
task format            # Format all Go code
task format:check      # Check if code is formatted
task lint              # Run go vet
task lint:full         # Advanced linting with golangci-lint

# Building
task build             # Build the module
task build:examples    # Build example binaries

# Development
task dev               # Run basic examples
task dev:certs         # Run certificate examples
task examples:run      # Run all examples

# Module Management
task mod:verify        # Verify dependencies
task mod:tidy          # Clean up dependencies
task mod:update        # Update all dependencies

# Cleanup
task clean             # Clean build artifacts
task clean:cache       # Clean Go cache
task clean:all         # Clean everything

# CI/CD
task ci                # Run complete CI pipeline locally
task release:check     # Check if ready for release

# Git Operations
task git:status        # Show git status
task git:commit -- "message"  # Commit with message
```

### Manual Commands (Alternative)

```bash
# Testing
go test ./...
go test -v ./...
go test ./keypair -v
go test ./cert -v
go test ./signing -v
go test ./encryption -v
go test -run TestGenerateRSAKeyPair ./keypair -v

# Building
go build ./...
go mod verify
go mod tidy

# Code Quality
go fmt ./...
go vet ./...

# Examples
cd examples/keypair && go run main.go
cd examples/certificates && go run main.go
cd examples/signing && go run main.go
cd examples/encryption && go run main.go
```

## Architecture Overview

GoPKI is a type-safe Go library for PKI operations using **generic constraints for compile-time safety**. This library focuses on generic abstractions and avoids `any` or `interface{}` types unless absolutely necessary, ensuring maximum type safety through Go's generic system.

### Core Modules

**`keypair/`** - Cryptographic key pair generation and management
- Generic interfaces with compile-time type safety using Go generics
- Support for RSA (2048+ bits), ECDSA (P-224/P-256/P-384/P-521), Ed25519
- Unified API through `GenerateKeyPair[T Param, K KeyPair](param T)` function
- Algorithm-specific implementations in `keypair/algo/`

**`cert/`** - X.509 certificate creation and management  
- Self-signed certificates and CA certificate creation
- Certificate signing with intermediate CA support
- Path length constraints for CA hierarchies
- Integrates with keypair module through generic constraints

**`signing/`** - Document signing and signature verification
- Digital signatures with RSA, ECDSA, and Ed25519 algorithms
- Industry-standard PKCS#7/CMS format support (attached and detached)
- Raw signature format for custom applications
- Certificate integration for complete signature verification
- Streaming API for large document signing

**`encryption/`** - Type-safe data encryption and decryption functionality
- **Pure generic interfaces** with compile-time type safety using Go generics
- Multiple encryption algorithms (RSA-OAEP, ECDH+AES-GCM, X25519+AES-GCM)
- RFC 5652 CMS (Cryptographic Message Syntax) format support using external library
- Envelope encryption for large data sets with multiple recipients
- Certificate-based encryption workflows with **strongly-typed APIs**
- **Generic constraints from keypair module** for all function signatures

**`keypair/format/`** - Key format conversion utilities
- PEM/DER format interchange
- SSH public key format support
- Cross-format conversion capabilities

**`examples/`** - Working demonstrations
- `keypair/` - Key generation, format conversion, and SSH support
- `certificates/` - Advanced PKI with CA hierarchies and certificate chains
- `signing/` - Document signing with multi-algorithm and PKCS#7/CMS support
- `encryption/` - Data encryption with type-safe APIs and CMS format support

### Generic Type System

The library uses Go generics for type safety:

```go
// Parameter constraints for key generation
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair type constraints
type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// Private key type constraints (used across modules)
type PrivateKey interface {
    *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}
```

Usage patterns:
```go
// RSA key generation with type safety
rsaKeys, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// ECDSA key generation
ecdsaKeys, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)

// Type-safe CMS decryption with automatic type inference (preferred)
decrypted, err := encryption.DecodeFromCMS(cmsData, cert, rsaKeys.PrivateKey)

// Explicit type parameter for CMS decryption
decrypted, err := encryption.DecodeFromCMS[*rsa.PrivateKey](cmsData, cert, rsaKeys.PrivateKey)

// Using the wrapper function with type constraints
decrypted, err := encryption.DecodeDataWithKey(cmsData, cert, rsaKeys.PrivateKey)
```

### Algorithm Implementation Structure

Each algorithm has its own package in `keypair/algo/`:
- `rsa.go` - RSA key operations with KeySize parameter
- `ecdsa.go` - ECDSA operations with ECDSACurve parameter  
- `ed25519.go` - Ed25519 operations with Ed25519Config parameter

### Certificate Operations

Certificate creation follows a request-based pattern:
```go
certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "example.com"},
    DNSNames: []string{"example.com", "www.example.com"},
    ValidFor: 365 * 24 * time.Hour,
})
```

CA certificates support path length constraints for controlling certificate chain depth.

### Document Signing Operations

The library includes a complete document signing module with PKCS#7/CMS support:
```go
// Basic document signing
signature, err := signing.SignDocument(data, keyPair, certificate, signing.SignOptions{
    Format: signing.FormatPKCS7,
    HashAlgorithm: crypto.SHA256,
    IncludeCertificate: true,
})

// Verify signature
err = signing.VerifySignature(data, signature, signing.DefaultVerifyOptions())
```

Signing supports:
- Multi-algorithm support (RSA, ECDSA, Ed25519)
- Multiple signature formats (Raw, PKCS#7/CMS attached/detached)
- Certificate integration and verification
- Streaming API for large documents

### Data Encryption Operations

The library includes comprehensive encryption functionality with type-safe CMS support:
```go
// Basic encryption using external Mozilla PKCS7 library
import "github.com/jasoet/gopki/encryption"

// Create encrypted data with type-safe recipient handling
encData := &encryption.EncryptedData{
    Algorithm: encryption.AlgorithmEnvelope,
    Format:    encryption.FormatCMS,
    Data:      plaintext,
    Recipients: []*encryption.RecipientInfo{
        {
            Certificate:            recipientCert,
            KeyEncryptionAlgorithm: encryption.AlgorithmRSAOAEP,
        },
    },
}

// Encode to CMS format using external library
cmsData, err := encryption.EncodeToCMS(encData)

// Type-safe decryption with automatic type inference (preferred)
decrypted, err := encryption.DecodeFromCMS(cmsData, cert, privateKey)

// Alternative with explicit type parameter
decrypted, err := encryption.DecodeFromCMS[*rsa.PrivateKey](cmsData, cert, rsaPrivateKey)

// Using wrapper function with keypair.PrivateKey constraint
decrypted, err := encryption.DecodeDataWithKey(cmsData, cert, privateKey)
```

The encryption module features:
- RFC 5652 CMS format using `go.mozilla.org/pkcs7` external library
- **Pure generic interfaces** with compile-time type safety
- Support for RSA, ECDSA, and Ed25519 private key types using `keypair.PrivateKey` constraints
- Envelope encryption for large data with multiple recipients
- **Strongly-typed certificate-based encryption** workflows
- Collection of functions rather than complex interfaces

## Key Development Patterns

### Generic Abstraction Focus
This library prioritizes **generic abstractions** over `any` or `interface{}` types:
- Use specific type constraints from `keypair.PrivateKey`, `keypair.PublicKey`, `keypair.KeyPair`
- Avoid `any` or `interface{}` in function/method signatures unless absolutely necessary
- `any` is acceptable for metadata storage (`map[string]any`) and external library compatibility
- Prefer compile-time type safety through Go's generic system for core APIs
- Functions are designed as collections rather than complex interface hierarchies

### Type-Safe Key Generation
Always use the generic `GenerateKeyPair` function with proper type constraints. The compiler will catch type mismatches at build time.

### Error Handling
All functions return explicit errors. Key generation enforces minimum security standards (e.g., RSA keys must be ≥2048 bits).

### File Operations
The library includes utilities for saving keys and certificates with proper file permissions. Use the provided functions rather than manual file I/O.

### Testing Strategy
- Unit tests for each algorithm implementation
- Cross-compatibility tests between algorithms
- File I/O and error handling test coverage
- Integration tests with real certificate operations
- Document signing tests across all algorithms and formats
- PKCS#7/CMS format verification and parsing tests
- Encryption module tests with comprehensive generic type safety coverage
- CMS encryption/decryption round-trip testing with external library integration

### Generic API Design
The encryption module uses pure generic functions with type constraints:

```go
// Generic function with type constraints from keypair module
func DecodeDataWithKey[T keypair.PrivateKey](data []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error)

// Core CMS function allowing any type (for external library compatibility)
func DecodeFromCMS[T any](cmsData []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error)

// Generic interfaces for type safety
type Encryptor[K keypair.KeyPair] interface {
    Encrypt(data []byte, keyPair K, opts EncryptOptions) (*EncryptedData, error)
    SupportedAlgorithms() []EncryptionAlgorithm
}
```

API design principles:
- Use specific type constraints from `keypair` module for all function signatures
- Avoid `any` or `interface{}` in function parameters - prefer strong typing
- `any` is acceptable for metadata maps (`map[string]any`) and external library compatibility
- Generic interfaces provide compile-time type safety
- Collections of functions rather than complex inheritance hierarchies

### Format Conversions
Use the `keypair/format/` package for converting between PEM, DER, and SSH formats. This handles the complexity of format-specific encoding requirements.

## Module Dependencies

- `golang.org/x/crypto` - Extended cryptographic primitives
- `go.mozilla.org/pkcs7` - Standards-compliant CMS/PKCS#7 implementation
- `software.sslmate.com/src/go-pkcs12` - PKCS#12 format support
- Standard library packages: `crypto/*`, `encoding/pem`, `crypto/x509`

The module uses carefully selected external dependencies:
- Mozilla PKCS7 library provides battle-tested CMS implementation
- Minimal dependency footprint with focus on standard library compatibility
- External libraries chosen for security, standards compliance, and maintainability