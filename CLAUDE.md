# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GoPKI is a production-ready Go library for PKI (Public Key Infrastructure) operations that emphasizes **type-safe cryptography through Go generics**. The library provides comprehensive cryptographic functionality with 80.3% test coverage across 844+ tests and strict type safety throughout all APIs.

**Key Characteristics:**
- **Type-Safe Design**: Uses Go generics to eliminate `any`/`interface{}` types in core APIs
- **Security-First**: Enforces minimum key sizes, secure file permissions, and cryptographic best practices
- **Standards Compliant**: Full support for X.509, PKCS#7/CMS, PKCS#12, SSH formats
- **Production Ready**: Comprehensive testing, CI/CD pipeline, and semantic versioning

## Development Commands

### Using Taskfile (Recommended)

The project uses a comprehensive Taskfile for all development operations. Install Task from https://taskfile.dev/installation/

```bash
# Setup and Dependencies
task setup             # Initial project setup and dependency verification
task                   # Show all available tasks

# Testing (Primary Development Commands)
task test              # Run all tests with race detection (80.3% coverage)
task test:verbose      # Verbose test output with detailed results
task test:coverage     # Generate HTML coverage report
task test:specific -- TestName  # Run specific test by name
task test:compatibility # Run compatibility tests with OpenSSL and ssh-keygen

# Code Quality and Analysis
task format            # Format all Go code (go fmt)
task format:check      # Verify code formatting without changes
task lint              # Basic linting with go vet
task lint:full         # Comprehensive linting with golangci-lint
task lint:security     # Security-focused linting (gosec, ineffassign)
task deadcode          # Find unused/dead code
task unused:all        # Run all unused code detection tools

# Building and Examples
task build             # Build the entire module
task build:examples    # Build example binaries with 'example' build tag
task examples:run      # Run all examples sequentially
task examples:keypair  # Run keypair examples only
task examples:certificates  # Run certificate examples only
task examples:signing  # Run signing examples only
task examples:encryption    # Run encryption examples only

# Module Management
task mod:verify        # Verify module dependencies
task mod:tidy          # Clean up dependencies
task mod:update        # Update all dependencies to latest versions

# Cleanup Operations
task clean             # Clean build artifacts and generated files
task clean:cache       # Clean Go build and test cache
task clean:all         # Clean everything including module cache
task examples:clean    # Clean example output directories

# CI/CD Pipeline
task ci                # Run complete CI pipeline locally
task ci:full           # Comprehensive CI with all checks and examples
task pre-commit        # Pre-commit checks (format, lint, basic tests)
task release:check     # Check if ready for release

# Documentation and Development
task docs:generate     # Generate API documentation
task docs:serve        # Start godoc server on http://localhost:6060
task git:status        # Show git status and current branch
task git:commit -- "message"  # Commit with standardized message format
```

### Manual Commands (Fallback)

If Taskfile is unavailable, use these manual commands:

```bash
# Core Testing
go test ./... -race -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Compatibility Testing
go test -tags=compatibility ./compatibility/...

# Building
go build ./...
go mod verify && go mod tidy

# Code Quality
go fmt ./...
go vet ./...

# Examples (with build tags)
go run -tags example ./examples/keypair/main.go
go run -tags example ./examples/certificates/main.go
go run -tags example ./examples/signing/main.go
go run -tags example ./examples/encryption/main.go
```

## Architecture Overview

GoPKI provides a **type-safe, generic-first approach** to PKI operations. The library is structured as five core modules with strong type relationships and comprehensive format support.

### Core Design Principles

1. **Generic Type Safety**: Compile-time type safety through Go generics, avoiding `any` types
2. **Security by Default**: Enforced minimum key sizes, secure file permissions, cryptographic best practices
3. **Standards Compliance**: Full support for industry standards (X.509, PKCS#7, PKCS#12, SSH)
4. **Modular Architecture**: Independent modules with clean interfaces and integration points
5. **Format Agnostic**: Seamless conversion between PEM, DER, SSH, and binary formats

### Module Structure and Dependencies

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

## Core Modules

### 1. `keypair/` - Foundation Module (Primary)

**Purpose**: Type-safe cryptographic key pair generation and management
**Test Coverage**: 75.3%
**Key Files**: `keypair.go` (2,115 lines), `algo/rsa.go`, `algo/ecdsa.go`, `algo/ed25519.go`

**Core Generic Types:**
```go
// Parameter constraints for key generation
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair type constraints
type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// Private key constraints (used across all modules)
type PrivateKey interface {
    *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// Public key constraints
type PublicKey interface {
    *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}
```

**Primary APIs:**
```go
// Unified key pair manager with full type safety
type Manager[K KeyPair, P PrivateKey, B PublicKey] struct { /* ... */ }

// Generic key generation factory
func Generate[T Param, K KeyPair, P PrivateKey, B PublicKey](param T) (*Manager[K, P, B], error)

// Algorithm-specific generation functions
func algo.GenerateRSAKeyPair(keySize algo.KeySize) (*algo.RSAKeyPair, error)    // keySize: KeySize2048, KeySize3072, KeySize4096
func algo.GenerateECDSAKeyPair(curve algo.ECDSACurve) (*algo.ECDSAKeyPair, error) // curve: P224, P256, P384, P521
func algo.GenerateEd25519KeyPair() (*algo.Ed25519KeyPair, error)

// Format conversion with type safety
func keypair.ToPEMFiles[T KeyPair](keyPair T, privateFile, publicFile string) error
func keypair.PrivateKeyToPEM[T PrivateKey](privateKey T) (format.PEM, error)
func keypair.PublicKeyToSSH[T PublicKey](publicKey T, comment string) (format.SSH, error)
```

**Security Features:**
- **Enforced Minimum Key Sizes**: RSA keys must be ≥2048 bits (compile-time checked)
- **Secure File Permissions**: Private keys saved with 0600 permissions, directories with 0700
- **Memory Safety**: No raw cryptographic material exposure
- **Format Validation**: Type-safe conversions prevent format mismatches

**Supported Algorithms:**
- **RSA**: 2048, 3072, 4096-bit keys with PKCS#8 encoding
- **ECDSA**: P-224, P-256, P-384, P-521 curves
- **Ed25519**: 256-bit keys with high performance

### 2. `cert/` - X.509 Certificate Management

**Purpose**: X.509 certificate creation, CA operations, and certificate chain management
**Test Coverage**: 74.3%
**Integration**: Uses `keypair/` module for all key operations

**Core Types:**
```go
type Certificate struct {
    Certificate *x509.Certificate  // Parsed certificate
    PEMData     []byte            // PEM-encoded certificate
    DERData     []byte            // DER-encoded certificate
}

type CertificateRequest struct {
    Subject      pkix.Name        // Certificate subject
    DNSNames     []string         // Subject Alternative Names
    IPAddresses  []net.IP         // IP address SANs
    EmailAddress []string         // Email SANs
    ValidFrom    time.Time        // Certificate validity start
    ValidFor     time.Duration    // Validity period
    IsCA         bool            // CA certificate flag
    MaxPathLen   int             // Path length constraint for CAs
}
```

**Primary APIs:**
```go
// Self-signed certificate creation
func CreateSelfSignedCertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error)

// CA certificate creation with constraints
func CreateCACertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error)

// Certificate signing by CA
func SignCertificate[T keypair.KeyPair](caCert *Certificate, caKeyPair T, request CertificateRequest, publicKey crypto.PublicKey) (*Certificate, error)

// Certificate verification
func VerifyCertificate(cert *Certificate, caCert *Certificate) error

// File operations
func (c *Certificate) SaveToFile(filename string) error
func LoadCertificateFromFile(filename string) (*Certificate, error)
func ParseCertificateFromPEM(pemData []byte) (*Certificate, error)
```

**CA Features:**
- **Path Length Constraints**: Control intermediate CA depth in certificate chains
- **BasicConstraints Extension**: Proper CA flag and path length handling
- **Key Usage Extensions**: Automatic CertSign and CRLSign for CA certificates
- **Certificate Chain Validation**: Full chain verification support

### 3. `signing/` - Digital Signatures and Verification

**Purpose**: Document signing, signature verification, and PKCS#7/CMS format support
**Test Coverage**: 79.8% (core), 77.2% (formats)
**Key Files**: `signing.go`, `signer.go`, `verifier.go`, `formats/`

**Core Types:**
```go
type Signature struct {
    Format           SignatureFormat     // raw, pkcs7, pkcs7-detached
    Algorithm        SignatureAlgorithm  // rsa, ecdsa, ed25519
    HashAlgorithm    crypto.Hash         // SHA256, SHA384, SHA512
    Data             []byte              // Signature bytes
    Digest           []byte              // Document digest
    Certificate      *x509.Certificate   // Signer certificate
    CertificateChain []*x509.Certificate // Certificate chain
    Timestamp        *Timestamp          // RFC 3161 timestamp (optional)
    Metadata         map[string]any      // Additional signature metadata
}

type SignOptions struct {
    HashAlgorithm      crypto.Hash    // Hash algorithm for signing
    Format             SignatureFormat // Output signature format
    IncludeCertificate bool           // Include signer certificate
    IncludeChain       bool           // Include certificate chain
    Detached           bool           // Create detached signature
    TimestampURL       string         // TSA URL for timestamping
}
```

**Primary APIs:**
```go
// Document signing with full options
func SignData[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate, opts SignOptions) (*Signature, error)

// Simplified signing with defaults
func SignDocument[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate) (*Signature, error)

// Signature verification
func VerifySignature(data []byte, signature *Signature, opts VerifyOptions) error
func VerifyWithCertificate(data []byte, signature *Signature, certificate *x509.Certificate) error

// PKCS#7/CMS format operations
func CreatePKCS7Signature[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate, detached bool) ([]byte, error)
func VerifyPKCS7Signature(data []byte, pkcs7Data []byte) (*PKCS7Info, error)
```

**Signature Formats:**
- **Raw Signatures**: Algorithm-specific binary signatures (smallest size)
- **PKCS#7 Attached**: Signature with embedded document data
- **PKCS#7 Detached**: Signature separate from document (recommended)
- **Certificate Integration**: Automatic certificate chain inclusion
- **Timestamp Authority**: RFC 3161 timestamp token support

**Multi-Algorithm Support:**
- **RSA-PSS and RSA-PKCS1v15**: Both padding schemes supported
- **ECDSA**: All supported curves with deterministic signing
- **Ed25519**: High-performance pure signatures

### 4. `encryption/` - Type-Safe Data Encryption

**Purpose**: Data encryption/decryption with multiple algorithms and CMS format support
**Test Coverage**: 89.1% (highest coverage)
**Sophisticated Architecture**: 5 submodules with specialized functionality

**Submodule Structure:**
- `asymmetric/` (85.2%) - RSA, ECDSA, Ed25519 encryption implementations
- `symmetric/` (87.9%) - AES-GCM symmetric encryption
- `envelope/` (88.9%) - Envelope encryption for large data/multi-recipient
- `certificate/` (89.2%) - Certificate-based encryption workflows
- `cms.go` - CMS format integration with Mozilla PKCS#7 library

**Core Types:**
```go
type EncryptedData struct {
    Algorithm   EncryptionAlgorithm  // rsa-oaep, ecdh-aes-gcm, x25519-aes-gcm
    Format      EncryptionFormat     // raw, pkcs7, cms
    Data        []byte               // Encrypted data
    Recipients  []*RecipientInfo     // Multi-recipient support
    KeyInfo     *KeyEncryptionInfo   // Key derivation info
    Metadata    map[string]any       // Additional encryption metadata
}

type RecipientInfo struct {
    Certificate            *x509.Certificate    // Recipient certificate
    KeyEncryptionAlgorithm EncryptionAlgorithm  // Key encryption method
    EncryptedKey           []byte               // Encrypted symmetric key
}
```

**Primary APIs:**
```go
// Generic encryption interfaces
type Encryptor[K keypair.KeyPair] interface {
    Encrypt(data []byte, keyPair K, opts EncryptOptions) (*EncryptedData, error)
    SupportedAlgorithms() []EncryptionAlgorithm
}

// Type-safe decryption with generic constraints
func DecodeDataWithKey[T keypair.PrivateKey](data []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error)

// CMS format integration (external Mozilla library)
func EncodeToCMS(data *EncryptedData) ([]byte, error)
func DecodeFromCMS[T any](cmsData []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error)

// High-level encryption functions
func EncryptForCertificate(data []byte, cert *x509.Certificate, opts EncryptOptions) (*EncryptedData, error)
func DecryptWithKeyPair[T keypair.KeyPair](encData *EncryptedData, keyPair T) ([]byte, error)
```

**Encryption Algorithms:**
- **RSA-OAEP**: Direct RSA encryption (limited to ~190 bytes for RSA-2048)
- **ECDH + AES-GCM**: ECDSA key agreement + symmetric encryption (recommended)
- **X25519 + AES-GCM**: Ed25519-based key agreement + symmetric encryption
- **Envelope Encryption**: Hybrid encryption for large data with multiple recipients

**Format Support:**
- **Raw Binary**: Algorithm-specific encrypted output
- **PKCS#7 EnvelopedData**: Standards-compliant envelope format
- **CMS (RFC 5652)**: Full Cryptographic Message Syntax support

### 5. `pkcs12/` - PKCS#12 File Management

**Purpose**: PKCS#12 file creation, loading, and integration with other modules
**Test Coverage**: 79.1%
**Integration**: Seamless integration with keypair and cert modules

**Core Types:**
```go
type Container struct {
    PrivateKey       interface{}        // Private key (any algorithm)
    Certificate      *x509.Certificate  // Primary certificate
    CertificateChain []*x509.Certificate // Certificate chain
    FriendlyName     string             // Human-readable name
}

type LoadOptions struct {
    Password         string    // PKCS#12 password
    TrustedCerts     []*x509.Certificate // Trusted CA certificates
    SkipVerification bool      // Skip certificate chain verification
}

type CreateOptions struct {
    Password     string  // PKCS#12 password
    FriendlyName string  // Container friendly name
    Iterations   int     // Key derivation iterations (security vs performance)
}
```

**Primary APIs:**
```go
// PKCS#12 file operations
func LoadFromP12File(filename string, opts LoadOptions) (*Container, error)
func CreateP12File(filename string, privateKey interface{}, cert *x509.Certificate, chain []*x509.Certificate, opts CreateOptions) error

// Convenience functions
func QuickLoadP12(filename, password string) (*Container, error)
func GenerateTestP12(filename, password string) error

// Integration with other modules
func LoadKeyPairFromP12[T keypair.KeyPair](filename, password string) (T, *cert.Certificate, error)
func SaveKeyPairToP12[T keypair.KeyPair](keyPair T, certificate *cert.Certificate, filename, password string) error
```

## Format Support Matrix

GoPKI provides comprehensive format conversion support across all algorithms:

| Format | RSA | ECDSA | Ed25519 | Usage |
|--------|-----|-------|---------|-------|
| **PEM** | ✅ | ✅ | ✅ | Text-based, Base64 encoded, most common |
| **DER** | ✅ | ✅ | ✅ | Binary format, ~30% smaller than PEM |
| **SSH** | ✅ | ✅ | ✅ | OpenSSH format for authorized_keys |
| **PKCS#12** | ✅ | ✅ | ✅ | Password-protected container format |

**Format Conversion APIs:**
```go
// Cross-format conversion utilities
func keypair.ToPEMFiles[T KeyPair](keyPair T, privateFile, publicFile string) error
func keypair.ToDERFiles[T KeyPair](keyPair T, privateFile, publicFile string) error
func keypair.ToSSHFiles[T KeyPair](keyPair T, privateFile, publicFile string, comment, passphrase string) error

// Loading from different formats
func keypair.LoadFromPEM[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string) (*Manager[K, P, B], error)
func keypair.LoadFromDER[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string) (*Manager[K, P, B], error)
func keypair.LoadFromSSH[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string, passphrase string) (*Manager[K, P, B], error)
```

## Examples and Usage Patterns

### Example Build Tags

All examples use the `//go:build example` build tag to exclude them from regular builds and testing:

```go
//go:build example

package main
```

**Running Examples:**
```bash
task examples:run          # Run all examples
task examples:keypair      # Run keypair examples only
task examples:certificates # Run certificate examples only
task examples:signing      # Run signing examples only
task examples:encryption   # Run encryption examples only
```

### 1. Key Generation Examples (`examples/keypair/main.go`)

**Demonstrates:**
- RSA, ECDSA, Ed25519 key generation with proper type constraints
- Format conversion matrix (PEM, DER, SSH)
- SSH key format support with comments and passphrases
- Certificate integration for self-signed certificates
- Format detection and validation

### 2. Certificate Examples (`examples/certificates/main.go`)

**Demonstrates:**
- CA certificate creation with path length constraints
- Intermediate CA certificate signing
- Server certificate creation with SANs (DNS names, IP addresses)
- Certificate chain verification
- Self-signed certificate workflows

### 3. Signing Examples (`examples/signing/main.go`)

**Demonstrates:**
- Multi-algorithm document signing (RSA, ECDSA, Ed25519)
- PKCS#7/CMS signature formats (attached and detached)
- Certificate chain inclusion in signatures
- Signature verification workflows
- Multi-signature document workflows
- Timestamp Authority integration

### 4. Encryption Examples (`examples/encryption/main.go`)

**Demonstrates:**
- RSA-OAEP encryption for small data
- ECDH + AES-GCM hybrid encryption
- X25519 + AES-GCM high-performance encryption
- Envelope encryption for large data
- Multi-recipient encryption workflows
- CMS format encryption/decryption

## Testing Strategy and Quality Assurance

### Comprehensive Test Coverage

**Overall Statistics:**
- **Total Coverage**: 80.3%
- **Total Tests**: 844+ individual tests across 23 test files
- **Test Types**: Unit, Integration, Security, Benchmark, Edge Case

**Module Coverage Breakdown:**
```
encryption/           89.1% (highest - most complex module)
  asymmetric/         85.2%
  symmetric/          87.9%
  envelope/           88.9%
  certificate/        89.2%

keypair/algo/         87.8% (algorithm implementations)
signing/              79.8% (core signing)
  formats/            77.2% (PKCS#7/CMS formats)
pkcs12/               79.1% (PKCS#12 operations)
cert/                 74.3% (certificate operations)
keypair/              75.3% (manager and utilities)
```

### Test Categories

**1. Algorithm Tests:**
- Key generation validation across all algorithms
- Format conversion round-trip testing
- Cross-algorithm compatibility verification
- Security parameter enforcement (minimum key sizes)

**2. Integration Tests:**
- Module-to-module data flow verification
- Certificate signing with generated keys
- Document signing with certificates
- Encryption/decryption with certificate keys

**3. Security Tests:**
- Key validation and strength verification
- File permission enforcement testing
- Cryptographic parameter validation
- Format integrity verification

**4. Performance Tests:**
- Benchmark tests for all algorithms
- Memory usage profiling
- Large data handling verification
- Multi-recipient encryption performance

**5. Edge Case Tests:**
- Error handling and validation
- Invalid input rejection
- Malformed data handling
- Resource exhaustion scenarios

### Quality Assurance Tools

**Linting and Static Analysis:**
```bash
task lint:full         # golangci-lint comprehensive analysis
task lint:security     # Security-focused linting (gosec)
task deadcode          # Unused code detection
task unused:all        # Comprehensive unused code analysis
```

**Security Scanning:**
```bash
task security:check    # Dependency vulnerability scanning
```

## Dependencies and External Libraries

### Core Dependencies (Minimal and Carefully Selected)

**From `go.mod`:**
- `go.mozilla.org/pkcs7 v0.9.0` - Battle-tested CMS/PKCS#7 implementation
- `golang.org/x/crypto v0.42.0` - Extended cryptographic primitives and SSH support
- `software.sslmate.com/src/go-pkcs12 v0.6.0` - Standards-compliant PKCS#12 implementation

**Testing Dependencies:**
- `github.com/stretchr/testify v1.11.1` - Testing framework and assertions

**Design Philosophy:**
- **Minimal Dependencies**: Only essential, well-maintained libraries
- **Security Focus**: All dependencies chosen for security and standards compliance
- **Standard Library First**: Maximum use of Go standard library cryptographic packages
- **Battle-Tested Libraries**: Dependencies with proven track records in production

### Dependency Integration Patterns

**Mozilla PKCS#7 Integration:**
```go
// GoPKI wraps external library with type-safe interfaces
func EncodeToCMS(data *EncryptedData) ([]byte, error) {
    // Convert GoPKI types to Mozilla PKCS7 format
    // Provide type-safe wrapper around external library
}

func DecodeFromCMS[T any](cmsData []byte, cert *x509.Certificate, privateKey T) (*EncryptedData, error) {
    // Parse Mozilla PKCS7 format
    // Convert back to GoPKI types with full type safety
}
```

## Security Best Practices and Compliance

### Cryptographic Security

**Key Generation Security:**
- **Strong Random Sources**: Uses `crypto/rand.Reader` exclusively
- **Minimum Key Sizes**: RSA ≥2048 bits enforced at compile time
- **Secure Curves**: Only NIST P-curves and Ed25519 supported
- **Parameter Validation**: All cryptographic parameters validated before use

**Algorithm Security:**
- **RSA-OAEP**: OAEP padding prevents padding oracle attacks
- **ECDSA**: Deterministic signatures prevent nonce reuse vulnerabilities
- **Ed25519**: Immune to timing attacks and implementation errors
- **AES-GCM**: Authenticated encryption prevents tampering

### File System Security

**File Permissions:**
```go
// Enforced throughout the library
privateKeyFiles := 0600  // Owner read/write only
publicKeyFiles := 0600   // Consistent permissions
directories := 0700      // Owner access only
```

**Secure File Handling:**
- Atomic file operations where possible
- Temporary file cleanup
- Proper error handling for file operations
- Directory creation with secure permissions

### Memory Security

**Secure Memory Handling:**
- No raw key material exposure in APIs
- Proper zeroing of sensitive data (where possible in Go)
- Defensive copying of cryptographic parameters
- Type safety prevents memory corruption

### Standards Compliance

**Supported Standards:**
- **RFC 5652**: Cryptographic Message Syntax (CMS)
- **RFC 3447**: PKCS #1: RSA Cryptography Specifications
- **RFC 5208**: PKCS #8: Private-Key Information Syntax
- **RFC 7748**: Elliptic Curves for Security (Ed25519, X25519)
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate
- **RFC 2585**: Internet X.509 Public Key Infrastructure Operational Protocols: FTP and HTTP
- **PKCS #7**: Cryptographic Message Syntax Standard
- **PKCS #12**: Personal Information Exchange Syntax Standard

## Development Workflow and CI/CD

### Git Workflow

**Commit Standards:**
```bash
task git:commit -- "feat: add Ed25519 encryption support"
task git:commit -- "fix: resolve RSA key size validation"
task git:commit -- "docs: update API documentation"
```

**Pre-commit Workflow:**
```bash
task pre-commit        # Run format, lint, and basic tests
task format             # Format code before commit
task lint:security     # Security checks before commit
```

### Continuous Integration

**GitHub Actions Integration:**
- **Semantic Release**: Automated versioning and changelog generation
- **Node.js 20** environment for semantic-release tooling
- **Automated Tagging**: Git tags created automatically for releases

**Local CI Pipeline:**
```bash
task ci                # Complete CI pipeline locally
task ci:full           # Comprehensive CI with all checks
task release:check     # Verify release readiness
```

### Release Management

**Semantic Versioning:**
- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, security updates

**Release Checklist (Automated):**
1. All tests pass (80.3% coverage maintained)
2. Code formatting verified
3. Security linting passes
4. Documentation updated
5. Examples functional
6. Changelog generated automatically

## Key Development Patterns

### Generic-First Design

**Core Pattern:**
```go
// Define type constraints
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// Use constraints in function signatures
func GenerateKeyPair[T Param, K KeyPair](param T) (K, error) {
    // Implementation with compile-time type safety
}
```

**Benefits:**
- **Compile-time Safety**: Type mismatches caught at build time
- **Zero Runtime Overhead**: Generics compile to efficient code
- **API Consistency**: Same interface pattern across all algorithms
- **IntelliSense Support**: Better IDE support with concrete types

### Format Abstraction

**Type-Safe Format Definitions:**
```go
// Package format provides type-safe format abstractions
type PEM []byte     // PEM-encoded data with validation
type DER []byte     // DER-encoded binary data
type SSH string     // SSH public/private key format
```

**Conversion Pattern:**
```go
// All format conversions follow same pattern
func PrivateKeyToPEM[T PrivateKey](privateKey T) (format.PEM, error)
func PrivateKeyToDER[T PrivateKey](privateKey T) (format.DER, error)
func PrivateKeyToSSH[T PrivateKey](privateKey T, comment, passphrase string) (format.SSH, error)
```

### Error Handling Strategy

**Explicit Error Returns:**
- All functions return explicit error values
- No panics in library code
- Detailed error messages with context
- Wrapped errors preserve original error information

**Error Types:**
- Validation errors for invalid parameters
- Cryptographic errors for algorithm failures
- I/O errors for file operations
- Format errors for data parsing failures

### Security-First Development

**Parameter Validation:**
```go
// Example: RSA key size validation
func GenerateRSAKeyPair(keySize KeySize) (*RSAKeyPair, error) {
    bits := keySize.Bits()
    if bits < 2048 {
        return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
    }
    // ... secure generation
}
```

**Secure Defaults:**
- Minimum security parameters enforced
- Secure algorithms chosen by default
- Safe file permissions applied automatically
- Strong random number generation used exclusively

## Integration Examples

### Full PKI Workflow

```go
// 1. Generate CA key pair
caKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize3072)

// 2. Create CA certificate
caCert, _ := cert.CreateCACertificate(caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "My Root CA"},
    ValidFor: 10 * 365 * 24 * time.Hour,
})

// 3. Generate server key pair
serverKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// 4. Create server certificate signed by CA
serverCert, _ := cert.SignCertificate(caCert, caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "server.example.com"},
    DNSNames: []string{"server.example.com", "api.example.com"},
    ValidFor: 365 * 24 * time.Hour,
}, serverKeys.PublicKey)

// 5. Sign a document with server certificate
document := []byte("Important contract")
signature, _ := signing.SignDocument(document, serverKeys, serverCert)

// 6. Verify signature
err := signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())

// 7. Encrypt data for server certificate
encData, _ := encryption.EncryptForCertificate([]byte("Secret data"), serverCert.Certificate, encryption.DefaultEncryptOptions())

// 8. Decrypt data with server private key
decrypted, _ := encryption.DecryptWithKeyPair(encData, serverKeys)

// 9. Save everything to PKCS#12 file
pkcs12.CreateP12File("server.p12", serverKeys.PrivateKey, serverCert.Certificate, []*x509.Certificate{caCert.Certificate}, pkcs12.CreateOptions{Password: "secure123"})
```

This comprehensive workflow demonstrates the seamless integration between all modules with full type safety throughout the entire process.

## Compatibility Testing Infrastructure

GoPKI includes extensive compatibility testing with industry-standard cryptographic tools to ensure seamless interoperability in production environments.

### Test Structure

**Compatibility test files use the `//go:build compatibility` build tag:**
```go
//go:build compatibility

package keypair
```

**Running Compatibility Tests:**
```bash
# Run all compatibility tests
task test:compatibility

# Manual execution
go test -tags=compatibility ./compatibility/...

# Run specific compatibility test suites
go test -tags=compatibility ./compatibility/keypair/...
go test -tags=compatibility ./compatibility/encryption/...
go test -tags=compatibility ./compatibility/signing/...
```

### OpenSSL Integration

**Core Helper Functions:**
The `compatibility/helpers.go` file provides OpenSSL integration helpers:

```go
// OpenSSL helper for cross-platform testing
type OpenSSLHelper struct {
    t       *testing.T
    tempDir string
}

// Key helper functions
func (h *OpenSSLHelper) GenerateSelfSignedCertWithOpenSSL(keyPEM []byte) ([]byte, error)
func (h *OpenSSLHelper) SignWithOpenSSL(data []byte, privateKeyPEM []byte, hashAlg string) ([]byte, error)
func (h *OpenSSLHelper) VerifyRawSignatureWithOpenSSL(data []byte, signature []byte, publicKeyPEM []byte, hashAlg string) error

// SSH-specific helpers
func (h *OpenSSLHelper) GetSSHKeyInformation(sshKey []byte) (string, error)
func (h *OpenSSLHelper) ValidateSSHPublicKeyWithSSHKeygen(sshKey []byte) error
func (h *OpenSSLHelper) ValidateSSHPrivateKeyWithSSHKeygen(sshKey []byte) error

// Encryption helpers
func (h *OpenSSLHelper) EncryptRSAOAEPWithOpenSSL(data []byte, publicKeyPEM []byte) ([]byte, error)
func (h *OpenSSLHelper) DecryptRSAOAEPWithOpenSSL(encryptedData []byte, privateKeyPEM []byte) ([]byte, error)
func (h *OpenSSLHelper) PerformECDHWithOpenSSL(privateKeyPEM []byte, peerPublicKeyPEM []byte) ([]byte, error)
```

### SSH Compatibility Testing

**SSH Key Validation:**
```go
// Test SSH key format compatibility with ssh-keygen
func TestSSHKeyValidation(t *testing.T) {
    helper := compatibility.NewOpenSSLHelper(t)
    defer helper.Cleanup()

    // Generate key with GoPKI
    manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
    _, publicSSH, _ := manager.ToSSH("test@example.com", "")

    // Validate with ssh-keygen
    err := helper.ValidateSSHPublicKeyWithSSHKeygen([]byte(publicSSH))
    assert.NoError(t, err, "ssh-keygen should validate GoPKI-generated SSH key")
}
```

**Advanced SSH Features:**
- SSH certificate information extraction
- SSH fingerprint generation and validation
- Multi-format conversion chains (PEM → SSH → PEM)
- Large comment handling and special characters
- Malformed key rejection testing

### Encryption Compatibility

**RSA-OAEP Cross-Testing:**
```go
func TestRSAOAEPBidirectional(t *testing.T) {
    // GoPKI encrypt → OpenSSL decrypt
    encrypted, _ := asymmetric.EncryptWithRSA(testData, rsaKeyPair, opts)
    decrypted, _ := helper.DecryptRSAOAEPWithOpenSSL(encrypted.Data, privatePEM)
    assert.Equal(t, testData, decrypted)

    // OpenSSL encrypt → GoPKI decrypt
    encrypted, _ := helper.EncryptRSAOAEPWithOpenSSL(testData, publicPEM)
    decrypted, _ := asymmetric.DecryptWithRSA(encData, rsaKeyPair, opts)
    assert.Equal(t, testData, decrypted)
}
```

**ECDH Key Agreement:**
```go
func TestECDHCompatibility(t *testing.T) {
    // Test ECDH key agreement using OpenSSL
    sharedSecret1, _ := helper.PerformECDHWithOpenSSL(privatePEM, ephemeralPublicPEM)
    sharedSecret2, _ := helper.PerformECDHWithOpenSSL(ephemeralPrivatePEM, publicPEM)
    assert.Equal(t, sharedSecret1, sharedSecret2, "ECDH shared secrets should match")
}
```

### Signature Interoperability

**Bidirectional Signature Testing:**
```go
func TestSignatureInteroperability(t *testing.T) {
    // OpenSSL sign → GoPKI verify
    signature, _ := helper.SignWithOpenSSL(testData, privatePEM, "sha256")
    verified := ed25519.Verify(publicKey, testData, signature)
    assert.True(t, verified, "GoPKI should verify OpenSSL signature")

    // GoPKI sign → OpenSSL verify
    signature := ed25519.Sign(privateKey, testData)
    err := helper.VerifyRawSignatureWithOpenSSL(testData, signature, publicPEM, "")
    assert.NoError(t, err, "OpenSSL should verify GoPKI signature")
}
```

### Compatibility Test Coverage

**Test Files and Coverage:**
- `compatibility/keypair/ssh_test.go` - Basic SSH compatibility (existing)
- `compatibility/keypair/ssh_advanced_test.go` - Advanced SSH features (new)
- `compatibility/encryption/encryption_test.go` - Encryption compatibility (new)
- `compatibility/signing/signing_test.go` - Signature compatibility (existing)
- `compatibility/cert/cert_test.go` - Certificate compatibility (existing)

**Compatibility Matrix Results:**
- **OpenSSL Certificate Compatibility**: 100% (all algorithms, all formats)
- **OpenSSH Key Compatibility**: 100% (all algorithms, advanced features)
- **OpenSSL Signature Compatibility**: 95% (Ed25519 PKCS#7 has expected limitations)
- **OpenSSL Encryption Compatibility**: Mixed (ECDH/X25519 100%, RSA-OAEP parameter differences)

### Real-World Validation

**Production Environment Testing:**
The compatibility tests validate GoPKI against real-world scenarios:
- Web server certificate deployment
- SSH key infrastructure integration
- Document signing workflows with existing PKI
- Cross-platform encryption/decryption
- Certificate chain validation with existing CAs

**External Tool Versions Tested:**
- OpenSSL 3.x (latest stable)
- ssh-keygen (OpenSSH 8.x+)
- Standard RFC compliance validation

This compatibility testing infrastructure ensures GoPKI works seamlessly with existing cryptographic infrastructure and tools in production environments.

## Important Instructions and Reminders

### Code Quality Standards

**NEVER:**
- Use `any` or `interface{}` in core API functions (exceptions: metadata maps, external library compatibility)
- Create files unless absolutely necessary for functionality
- Add unnecessary documentation files (only if explicitly requested)
- Violate the generic type constraints established in the keypair module
- Bypass security validations (minimum key sizes, secure permissions)

**ALWAYS:**
- Prefer editing existing files over creating new ones
- Follow the established generic type patterns
- Use the provided type constraints (`keypair.PrivateKey`, `keypair.PublicKey`, `keypair.KeyPair`)
- Maintain compile-time type safety throughout all changes
- Run `task test` before considering work complete
- Use `task format` to ensure proper code formatting
- Follow the security best practices established in the codebase

### Testing Requirements

**Before Any Changes:**
1. Run `task test` to ensure all tests pass (80.3% coverage maintained)
2. Run `task lint:full` for comprehensive code analysis
3. Run `task format:check` to verify formatting
4. Test examples with `task examples:run` if making API changes

**When Adding New Functionality:**
1. Write tests first (TDD approach preferred)
2. Maintain or improve code coverage
3. Follow established patterns for generic type constraints
4. Update examples if public API changes
5. Ensure integration tests pass across modules

### API Design Guidelines

**Generic Functions:**
```go
// GOOD: Specific type constraints
func ProcessKey[T keypair.PrivateKey](key T) error

// AVOID: Generic any types
func ProcessKey(key any) error
```

**Error Handling:**
```go
// GOOD: Explicit error returns with context
func GenerateKey(size int) (*Key, error) {
    if size < 2048 {
        return nil, fmt.Errorf("key size must be at least 2048 bits, got %d", size)
    }
    // ...
}

// AVOID: Panics or silent failures
func GenerateKey(size int) *Key {
    // panic on error - NEVER do this
}
```

**File Operations:**
```go
// GOOD: Secure permissions and error handling
func SavePrivateKey(key []byte, filename string) error {
    dir := filepath.Dir(filename)
    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    return os.WriteFile(filename, key, 0600)
}
```

This CLAUDE.md file provides comprehensive guidance for working with the GoPKI codebase while maintaining its high standards of type safety, security, and code quality.