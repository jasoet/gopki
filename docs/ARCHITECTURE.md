# GoPKI Architecture

**Complete system design and module relationships.**

## Overview

GoPKI is architected as **five independent but integrated modules** with a strong foundation in **Go generics for type safety**. The design prioritizes compile-time guarantees, security-first principles, and standards compliance.

## Module Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application Layer                     │
│           (Your code using GoPKI modules)                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     High-Level APIs                          │
│  EncryptForCertificate(), SignDocument(), CreateP12File()   │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│   signing/   │◄─────│    cert/     │◄─────│  pkcs12/     │
│  Digital     │      │ Certificates │      │   P12 Files  │
│  Signatures  │      └──────────────┘      └──────────────┘
└──────────────┘             │                      │
       │                     │                      │
       └─────────────────────┼──────────────────────┘
                             ▼
                    ┌──────────────┐
                    │ encryption/  │
                    │ Data         │
                    │ Encryption   │
                    └──────────────┘
                             │
                             ▼
                    ┌──────────────┐
                    │  keypair/    │
                    │ Foundation   │
                    │ (Type Safety)│
                    └──────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                  Go Standard Library + External              │
│   crypto/*, golang.org/x/crypto, go.mozilla.org/pkcs7      │
└─────────────────────────────────────────────────────────────┘
```

## Module Relationships

### 1. keypair/ - Foundation Module

**Purpose**: Type-safe key generation and management

**Exports**:
- Generic type constraints: `Param`, `KeyPair`, `PrivateKey`, `PublicKey`
- KeyPair Manager: Unified interface across algorithms
- Format conversions: PEM, DER, SSH, PKCS#12

**Dependencies**: Go standard library only

**Used By**: All other modules

**Critical Design**: All other modules reference keypair's type constraints. Changes here affect entire codebase.

### 2. cert/ - Certificate Management

**Purpose**: X.509 certificate operations

**Exports**:
- Certificate creation (self-signed, CA, end-entity)
- Certificate signing
- Chain verification

**Dependencies**:
- `keypair/` for key types
- `crypto/x509` for certificate operations

**Used By**: `signing/`, `encryption/`, `pkcs12/`

### 3. signing/ - Digital Signatures

**Purpose**: Document signing and verification

**Exports**:
- Multi-algorithm signing
- PKCS#7/CMS signatures
- Signature verification

**Dependencies**:
- `keypair/` for key constraints
- `cert/` for certificate integration
- `go.mozilla.org/pkcs7` for PKCS#7 format

**Used By**: Application layer (leaf module)

### 4. encryption/ - Data Encryption

**Purpose**: Multi-algorithm encryption with envelope support

**Architecture**: Most complex module with 5 submodules
- `asymmetric/` - RSA, ECDSA, Ed25519 encryption
- `symmetric/` - AES-GCM symmetric encryption
- `envelope/` - Hybrid envelope encryption
- `certificate/` - Certificate-based workflows
- `cms.go` - CMS format integration

**Exports**:
- Multiple encryption algorithms
- Envelope encryption (DEK + KEK pattern)
- CMS format encoding/decoding
- OpenSSL compatibility mode

**Dependencies**:
- `keypair/` for key constraints
- `cert/` for certificate operations
- `go.mozilla.org/pkcs7` for CMS format

**Used By**: Application layer (leaf module)

### 5. pkcs12/ - PKCS#12 File Management

**Purpose**: Bundle private keys with certificates

**Exports**:
- P12 file creation
- P12 file loading
- Cross-platform compatibility

**Dependencies**:
- `keypair/` for key types
- `cert/` for certificates
- `software.sslmate.com/src/go-pkcs12` for P12 format

**Used By**: Application layer (leaf module)

## Design Principles

### 1. Type Safety Through Generics

**Generic Constraints (keypair/keypair.go:50-150):**

```go
// Parameter types for key generation
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair types
type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// Private key types
type PrivateKey interface {
    *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// Public key types
type PublicKey interface {
    *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}
```

**Benefits**:
- Compile-time type checking
- No runtime type assertions
- IDE autocomplete support
- Zero performance overhead

**Usage Throughout Modules**:
```go
// In signing module
func SignData[T keypair.KeyPair](data []byte, keyPair T, ...) (*Signature, error)

// In encryption module
func DecryptWithKeyPair[T keypair.KeyPair](encData *EncryptedData, keyPair T) ([]byte, error)

// In cert module
func CreateSelfSignedCertificate[T keypair.KeyPair](keyPair T, ...) (*Certificate, error)
```

### 2. Security-First Design

**Enforced Security Standards:**
- Minimum RSA key size: 2048 bits (compile-time)
- Secure random source: `crypto/rand.Reader` only
- File permissions: 0600 (private keys), 0700 (directories)
- Authenticated encryption: AES-GCM only
- No raw key material exposure

**Security Validation Points:**
```
Key Generation → Validate Size
       ↓
File Operations → Enforce Permissions
       ↓
Crypto Operations → Validate Parameters
       ↓
Error Handling → No Information Leakage
```

### 3. Standards Compliance

**Implemented Standards:**
- **RFC 5652** - Cryptographic Message Syntax (CMS)
- **RFC 5280** - X.509 PKI Certificate
- **RFC 3447** - PKCS #1: RSA Cryptography
- **RFC 7748** - Elliptic Curves (Ed25519, X25519)
- **RFC 5208** - PKCS #8: Private-Key Information
- **PKCS #7** - Cryptographic Message Syntax
- **PKCS #12** - Personal Information Exchange
- **OpenSSH** - SSH key formats

### 4. Modular Independence

Each module can be used independently:
```go
// Use only keypair module
import "github.com/jasoet/gopki/keypair"

// Use only cert module (depends on keypair)
import (
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/cert"
)

// Full PKI workflow (all modules)
import (
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/signing"
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/pkcs12"
)
```

## Data Flow Patterns

### Pattern 1: Certificate-Based Encryption

```
1. keypair.Generate() → RSA key pair
                   ↓
2. cert.CreateSelfSignedCertificate() → X.509 certificate
                   ↓
3. encryption.EncryptForCertificate() → Encrypted data
                   ↓
4. encryption.DecryptWithKeyPair() → Plaintext
```

### Pattern 2: Document Signing Workflow

```
1. keypair.Generate() → Key pair
                   ↓
2. cert.CreateCACertificate() → CA certificate
                   ↓
3. signing.SignDocument() → Digital signature
                   ↓
4. signing.VerifySignature() → Verification result
```

### Pattern 3: Complete PKI Workflow

```
1. keypair.Generate() → CA key pair
                   ↓
2. cert.CreateCACertificate() → Root CA
                   ↓
3. keypair.Generate() → Server key pair
                   ↓
4. cert.SignCertificate() → Server certificate
                   ↓
5. pkcs12.CreateP12File() → P12 bundle
                   ↓
6. signing.SignDocument() + encryption.EncryptForCertificate()
```

## Envelope Encryption Architecture

**Most Complex Feature in GoPKI**

```
┌─────────────────────────────────────────────────────┐
│          Envelope Encryption (Hybrid)               │
│                                                     │
│  1. Generate random DEK (Data Encryption Key)      │
│                  32 bytes for AES-256              │
│                       ↓                            │
│  2. Encrypt data with DEK using AES-GCM           │
│       → Encrypted Data + IV + Tag                 │
│                       ↓                            │
│  3. For each recipient:                           │
│       Encrypt DEK with recipient's public key     │
│       → Encrypted DEK (KEK - Key Encryption Key)  │
│                       ↓                            │
│  4. Store: Encrypted Data + [Encrypted DEKs]      │
│                                                   │
│  Result: Large data encrypted once (fast),       │
│          DEK encrypted per recipient (secure)     │
└─────────────────────────────────────────────────────┘
```

**Benefits:**
- Large data support (GBs) - symmetric encryption is fast
- Multiple recipients - DEK encrypted once per recipient
- Optimal performance - hybrid approach
- OpenSSL compatibility - standard PKCS#7 EnvelopedData

## OpenSSL Integration Architecture

```
┌──────────────────────────────────────────────────────┐
│              GoPKI Encryption Modes                  │
├──────────────────────────────────────────────────────┤
│                                                      │
│  Standard Mode (Default):                           │
│  ┌────────────────────────────────────────┐        │
│  │ Custom GoPKI format                     │        │
│  │ • AES-256-GCM (authenticated)          │        │
│  │ • Envelope structure with metadata     │        │
│  │ • All algorithms supported             │        │
│  │ • Optimal for GoPKI ↔ GoPKI           │        │
│  └────────────────────────────────────────┘        │
│                                                      │
│  OpenSSL Compatible Mode:                           │
│  ┌────────────────────────────────────────┐        │
│  │ Standard PKCS#7 EnvelopedData           │        │
│  │ • AES-256-CBC (OpenSSL standard)       │        │
│  │ • RSA certificates only                 │        │
│  │ • Auto-detected on decode              │        │
│  │ • GoPKI ↔ OpenSSL interoperable       │        │
│  └────────────────────────────────────────┘        │
│                                                      │
│  Format Auto-Detection:                             │
│  ┌────────────────────────────────────────┐        │
│  │ DecodeFromCMS() checks:                 │        │
│  │ 1. Standard PKCS#7? → OpenSSL mode     │        │
│  │ 2. GoPKI metadata? → Standard mode     │        │
│  │ 3. Auto-decrypt if OpenSSL format      │        │
│  └────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────┘
```

## Testing Architecture

```
┌─────────────────────────────────────────────┐
│            Test Organization                │
├─────────────────────────────────────────────┤
│                                             │
│  Unit Tests (*_test.go):                   │
│  • Module-specific functionality           │
│  • 80.3% overall coverage                  │
│  • Table-driven test design                │
│                                             │
│  Integration Tests (examples/):            │
│  • Cross-module workflows                  │
│  • Real-world scenarios                    │
│  • Build tag: //go:build example           │
│                                             │
│  Compatibility Tests (compatibility/):     │
│  • OpenSSL integration                     │
│  • ssh-keygen validation                   │
│  • Build tag: //go:build compatibility     │
│  • Bidirectional testing                   │
│                                             │
│  Benchmark Tests (*_test.go):              │
│  • Performance validation                  │
│  • Algorithm comparisons                   │
│                                             │
└─────────────────────────────────────────────┘
```

**Test Execution Flow:**
```bash
task test                  # Unit + Integration tests
task test:coverage         # Coverage report
task test:compatibility    # OpenSSL/SSH tests
task examples:run          # Integration validation
```

## Error Handling Architecture

**Consistent Error Patterns:**
```go
// Module-specific error types
var (
    ErrInvalidKeySize = errors.New("keypair: invalid key size")
    ErrDataTooLarge = errors.New("encryption: data too large for algorithm")
    ErrInvalidCertificate = errors.New("cert: invalid certificate")
)

// Error wrapping with context
return nil, fmt.Errorf("failed to encrypt data: %w", err)

// Explicit error returns (no panics)
func DoOperation() (result *Result, err error)
```

**Error Handling Flow:**
```
Operation → Validate Input → Perform Crypto → Validate Output → Return Result/Error
     ↓            ↓                ↓                ↓                    ↓
  No panic    Clear error    Secure cleanup    Verify result     Wrapped context
```

## Performance Architecture

**Performance Optimization Strategies:**

1. **Zero-Cost Abstractions**: Generics compile to specialized code
2. **Minimal Allocations**: Reuse buffers where safe
3. **Streaming Support**: Large data handled incrementally (envelope encryption)
4. **Algorithm Selection**: Ed25519 > ECDSA > RSA for performance
5. **Caching**: Format conversions cached in Manager

**Performance Metrics:**
```
Key Generation:
  Ed25519:     1-2ms    ← Fastest
  ECDSA P-256: 5-10ms
  RSA-2048:    50-100ms

Signing:
  Ed25519:     ~0.1ms   ← Fastest
  ECDSA P-256: ~1ms
  RSA-2048:    ~1ms

Encryption (1MB):
  X25519+AES:  ~12ms    ← Fastest
  ECDH+AES:    ~15ms
  Envelope:    ~15ms
```

## Extension Points

**Adding New Algorithm:**
1. Define in `keypair/algo/newalgo.go`
2. Add to type constraints in `keypair/keypair.go:50-150`
3. Implement format conversions
4. Update downstream modules (cert, signing, encryption)
5. Add comprehensive tests
6. Test OpenSSL compatibility

**Adding New Format:**
1. Define format type in `keypair/format/format.go`
2. Add conversion functions in each algorithm
3. Add Manager support in `keypair/keypair.go`
4. Test cross-format conversions

**Adding New Encryption Algorithm:**
1. Create `encryption/asymmetric/newalgo.go`
2. Implement `Encryptor` and `Decryptor` interfaces
3. Add to algorithm dispatcher
4. Update envelope support if applicable
5. Add comprehensive tests

## Dependencies Architecture

**Dependency Hierarchy:**
```
Application Layer
       ↓
[signing, encryption, pkcs12]  ← Leaf modules
       ↓
     cert/                      ← Integration module
       ↓
   keypair/                     ← Foundation module
       ↓
[Go stdlib + minimal external]
```

**External Dependencies (Carefully Selected):**
- `go.mozilla.org/pkcs7` - Battle-tested PKCS#7/CMS
- `golang.org/x/crypto` - Extended crypto primitives
- `software.sslmate.com/src/go-pkcs12` - Standards-compliant P12

**Philosophy**: Minimal, security-focused, battle-tested dependencies only

## Security Architecture

**Defense in Depth:**
```
Application
    ↓ Input validation
API Layer
    ↓ Type safety (generics)
Module Logic
    ↓ Parameter validation
Crypto Operations
    ↓ Secure random, authenticated encryption
File Operations
    ↓ Secure permissions
Error Handling
    ↓ No information leakage
```

## Conclusion

GoPKI's architecture prioritizes:
- **Type Safety**: Generics provide compile-time guarantees
- **Security**: Defense in depth at every layer
- **Standards**: Full RFC compliance
- **Modularity**: Independent but integrated modules
- **Performance**: Zero-cost abstractions and optimal algorithms
- **Testability**: 80.3% coverage with comprehensive tests

The foundation in `keypair/` enables type-safe operations across all modules, while the modular design allows flexible usage patterns from simple key generation to complex PKI workflows.