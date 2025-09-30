# keypair/ - Type-Safe Key Generation and Management

**Foundation module providing type-safe cryptographic key pair generation and management through Go generics.**

[![Test Coverage](https://img.shields.io/badge/Coverage-75.3%25-green.svg)](https://github.com/jasoet/gopki)

## Overview

The `keypair` module is the foundation of GoPKI, providing:
- **Type-safe key generation** with compile-time guarantees
- **Unified KeyPair Manager** interface across all algorithms
- **Multi-format support** (PEM, DER, SSH, PKCS#12)
- **Secure file operations** with enforced permissions
- **Algorithm flexibility** (RSA, ECDSA, Ed25519)

## 🤖 AI Agent Quick Start

### File Structure Map

```
keypair/
├── keypair.go           - START HERE: Core types, Manager, generic constraints
│                         Lines 50-150: Type constraints (CRITICAL)
│                         Manager implementation, format conversions, file operations
├── algo/                - Algorithm implementations
│   ├── rsa.go          - RSA key generation and operations
│   │                     Structure, validation, generation (2048/3072/4096)
│   │                     Format conversions (PEM/DER/SSH), file operations
│   ├── ecdsa.go        - ECDSA operations (P-224/256/384/521)
│   │                     ECDSA structures, curves, generation, validation
│   │                     Format support, SSH format specifics
│   ├── ed25519.go      - Ed25519 high-performance signing
│   │                     Ed25519 structures, generation functions
│   │                     Format conversions, SSH format
│   ├── rsa_test.go     - Comprehensive RSA tests
│   ├── ecdsa_test.go   - ECDSA algorithm tests
│   └── ed25519_test.go - Ed25519 tests
└── format/             - Format definitions
    └── format.go       - Type-safe format abstractions (PEM, DER, SSH)
```

### Key Functions Location

| Function | File | Purpose |
|----------|------|---------|
| `Generate[T, K, P, B]()` | `keypair.go` | **Primary API** - Generic key generation factory |
| **Type Constraints** | `keypair.go:50-150` | **CRITICAL** - Read first: Param, KeyPair, PrivateKey, PublicKey |
| `Manager` struct | `keypair.go` | Unified interface for all key operations |
| `ToPEM()` | `keypair.go` | Convert Manager keys to PEM format |
| `ToSSH()` | `keypair.go` | Convert Manager keys to SSH format |
| `SaveToPEM()` | `keypair.go` | Save keys to PEM files (secure permissions) |
| `LoadFromPEM[K, P, B]()` | `keypair.go` | Load existing keys into Manager |
| `GenerateRSAKeyPair()` | `algo/rsa.go` | Direct RSA generation (alternative to Manager) |
| `GenerateECDSAKeyPair()` | `algo/ecdsa.go` | Direct ECDSA generation |
| `GenerateEd25519KeyPair()` | `algo/ed25519.go` | Direct Ed25519 generation |

### Common Modification Points

**Adding New Algorithm:**
1. Create `algo/newalgo.go` following pattern from `algo/rsa.go`
2. Define `NewAlgoKeyPair` struct with `PrivateKey` and `PublicKey` fields
3. Implement `GenerateNewAlgoKeyPair()` function (see RSA generation pattern)
4. Add format conversion methods following RSA patterns
5. Update type constraints in `keypair.go:50-150`
6. Add to test suite following `algo/rsa_test.go` patterns

**Adding New Format:**
1. Define format type in `format/format.go`
2. Add conversion functions in each `algo/*.go` file
3. Add Manager support in `keypair.go`
4. Add test coverage in `*_test.go` files

**Fixing Key Generation Bug:**
1. Check test expectations in relevant `algo/*_test.go`
2. Review generation logic in `algo/*.go` (generation functions)
3. Verify parameter validation (check minimum key sizes, curves)
4. Run: `task test:specific -- TestGenerateRSAKeyPair` (or relevant test)
5. Check format conversions aren't affected

### Type Relationships

```go
// Core type constraints (keypair.go:50-150)
// ALL modules in GoPKI use these constraints

// Parameter types for key generation
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair types (algorithm-specific structures)
type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// Private key types (crypto/... standard library types)
type PrivateKey interface {
    *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// Public key types
type PublicKey interface {
    *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// Usage pattern in this module:
func Generate[T Param, K KeyPair, P PrivateKey, B PublicKey](param T) (*Manager[K, P, B], error) {
    // Implementation provides compile-time type safety
}

// Usage pattern in OTHER modules (cert, signing, encryption):
func ProcessKey[T keypair.PrivateKey](key T) error {
    // Function works with all constraint types
}
```

**Critical Understanding:**
- These constraints are used by **ALL** modules in GoPKI
- Changing these affects `cert/`, `signing/`, `encryption/`, `pkcs12/` modules
- Always verify cross-module compatibility when modifying

### Dependencies

**This module depends on:**
- `crypto/rsa` - Standard library RSA support
- `crypto/ecdsa` - Standard library ECDSA support
- `crypto/ed25519` - Standard library Ed25519 support
- `golang.org/x/crypto/ssh` - SSH format support
- `encoding/pem` - PEM encoding/decoding
- `encoding/asn1` - DER format support

**Modules that depend on THIS:**
- `cert/` - Uses KeyPair types for certificate creation
- `signing/` - Uses PrivateKey constraints for document signing
- `encryption/` - Uses PublicKey/PrivateKey for encryption operations
- `pkcs12/` - Uses key types for P12 bundling

**Impact Warning:** Changes to type constraints in `keypair.go:50-150` affect ALL downstream modules!

### Testing Strategy

**Test Files:**
- `keypair_test.go` - Core Manager functionality tests
- `algo/rsa_test.go` - RSA algorithm-specific tests (1,234 lines)
- `algo/ecdsa_test.go` - ECDSA algorithm tests (1,156 lines)
- `algo/ed25519_test.go` - Ed25519 algorithm tests (892 lines)
- `compatibility/keypair/ssh_test.go` - SSH format compatibility with OpenSSH
- `compatibility/keypair/ssh_advanced_test.go` - Advanced SSH features

**Running Tests:**
```bash
# This module only
go test ./keypair/...

# Manager tests specifically
task test:specific -- TestManager

# Algorithm-specific
task test:specific -- TestGenerateRSAKeyPair
task test:specific -- TestECDSAKeyPair
task test:specific -- TestEd25519KeyPair

# SSH compatibility
task test:compatibility
```

**Test Coverage:** 75.3% (3,282 lines of tests)

### Related Documentation

- Algorithm details: [`docs/ALGORITHMS.md`](../docs/ALGORITHMS.md)
- Format guide: [`docs/FORMAT_GUIDE.md`](../docs/FORMAT_GUIDE.md) (when created)
- Usage examples: [`examples/keypair/main.go`](../examples/keypair/main.go)
- Example documentation: [`examples/keypair/doc.md`](../examples/keypair/doc.md)

---

## Features

### Supported Algorithms

| Algorithm | Key Sizes | Generation | Format Support | SSH Support |
|-----------|-----------|------------|----------------|-------------|
| **RSA** | 2048/3072/4096 bits | ✅ | PEM, DER, SSH, P12 | ✅ |
| **ECDSA** | P-224/256/384/521 curves | ✅ | PEM, DER, SSH, P12 | ✅ |
| **Ed25519** | 256-bit | ✅ | PEM, DER, SSH, P12 | ✅ |

### KeyPair Manager

The Manager provides a unified interface across all algorithms:

```go
type Manager[K KeyPair, P PrivateKey, B PublicKey] struct {
    // Unified interface for RSA, ECDSA, Ed25519
}
```

**Benefits:**
- **Type Safety**: Compile-time guarantees, no runtime type assertions
- **Unified API**: Same interface for all algorithms
- **Format Agnostic**: Easy conversion between PEM/DER/SSH/P12
- **Secure Operations**: Built-in secure file permissions

## Installation

```bash
go get github.com/jasoet/gopki/keypair
```

## Quick Start

### Method 1: Using KeyPair Manager (Recommended)

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA key pair with Manager
    manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
    if err != nil {
        panic(err)
    }

    // Extract keys with type safety
    privateKey := manager.PrivateKey()
    publicKey := manager.PublicKey()

    // Convert to different formats
    privatePEM, publicPEM, _ := manager.ToPEM()
    privateDER, publicDER, _ := manager.ToDER()
    privateSSH, publicSSH, _ := manager.ToSSH("user@host", "")

    // Save with secure permissions (0600 for private, 0644 for public)
    manager.SaveToPEM("private.pem", "public.pem")
    manager.SaveToSSH("id_rsa", "id_rsa.pub", "user@host", "")

    fmt.Printf("Generated %d-bit RSA key pair\n", privateKey.Size()*8)
}
```

### Method 2: Direct Algorithm Usage

```go
package main

import (
    "fmt"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA key pair directly
    rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // Generate ECDSA key pair
    ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)

    // Generate Ed25519 key pair
    ed25519Keys, _ := algo.GenerateEd25519KeyPair()

    fmt.Println("Keys generated successfully")
}
```

## API Reference

### Key Generation

#### Using Manager (Recommended)

```go
// Generic generation with Manager
func Generate[T Param, K KeyPair, P PrivateKey, B PublicKey](param T) (*Manager[K, P, B], error)

// Examples:
import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
)

// RSA Manager
manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)

// ECDSA Manager
manager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)

// Ed25519 Manager
manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
```

#### Direct Algorithm Functions

```go
// RSA (2048/3072/4096 bits)
func algo.GenerateRSAKeyPair(keySize algo.KeySize) (*algo.RSAKeyPair, error)

// ECDSA (P-224/P-256/P-384/P-521)
func algo.GenerateECDSAKeyPair(curve algo.ECDSACurve) (*algo.ECDSAKeyPair, error)

// Ed25519 (256-bit)
func algo.GenerateEd25519KeyPair() (*algo.Ed25519KeyPair, error)
```

### Manager Operations

```go
// Key extraction
func (m *Manager[K, P, B]) PrivateKey() P
func (m *Manager[K, P, B]) PublicKey() B
func (m *Manager[K, P, B]) KeyPair() K

// Format conversion
func (m *Manager[K, P, B]) ToPEM() (privateFormat.PEM, publicFormat.PEM, error)
func (m *Manager[K, P, B]) ToDER() (privateFormat.DER, publicFormat.DER, error)
func (m *Manager[K, P, B]) ToSSH(comment, passphrase string) (privateFormat.SSH, publicFormat.SSH, error)

// File operations (secure permissions: 0600 for private, 0644 for public)
func (m *Manager[K, P, B]) SaveToPEM(privateFile, publicFile string) error
func (m *Manager[K, P, B]) SaveToDER(privateFile, publicFile string) error
func (m *Manager[K, P, B]) SaveToSSH(privateFile, publicFile, comment, passphrase string) error

// Validation
func (m *Manager[K, P, B]) Validate() error
func (m *Manager[K, P, B]) IsValid() bool

// Metadata
func (m *Manager[K, P, B]) GetInfo() (*KeyInfo, error)
```

### Loading Existing Keys

```go
// Load into Manager from different formats
func LoadFromPEM[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string) (*Manager[K, P, B], error)
func LoadFromDER[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string) (*Manager[K, P, B], error)
func LoadFromSSH[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile, passphrase string) (*Manager[K, P, B], error)

// Example:
manager, _ := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("private.pem")
```

### Format Conversion (Direct Functions)

```go
// PEM format
func PrivateKeyToPEM[T PrivateKey](privateKey T) (format.PEM, error)
func PublicKeyToPEM[T PublicKey](publicKey T) (format.PEM, error)
func ParsePrivateKeyFromPEM[T PrivateKey](pemData format.PEM) (T, error)

// DER format
func PrivateKeyToDER[T PrivateKey](privateKey T) (format.DER, error)
func PublicKeyToDER[T PublicKey](publicKey T) (format.DER, error)

// SSH format
func PrivateKeyToSSH[T PrivateKey](privateKey T, comment, passphrase string) (format.SSH, error)
func PublicKeyToSSH[T PublicKey](publicKey T, comment string) (format.SSH, error)
```

## Usage Examples

### Complete Key Management Workflow

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // 1. Generate key pair
    manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
    if err != nil {
        panic(err)
    }

    // 2. Validate key pair
    if !manager.IsValid() {
        panic("Invalid key pair")
    }

    // 3. Get key information
    info, _ := manager.GetInfo()
    fmt.Printf("Algorithm: %s, Key Size: %d bits\n", info.Algorithm, info.KeySize)

    // 4. Save in multiple formats
    manager.SaveToPEM("keys/private.pem", "keys/public.pem")
    manager.SaveToDER("keys/private.der", "keys/public.der")
    manager.SaveToSSH("keys/id_rsa", "keys/id_rsa.pub", "user@host", "")

    // 5. Load existing key
    loaded, _ := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("keys/private.pem")

    // 6. Extract keys for use with other modules
    privateKey := loaded.PrivateKey()
    publicKey := loaded.PublicKey()

    fmt.Printf("Private key size: %d bits\n", privateKey.Size()*8)
    fmt.Printf("Public key: %v\n", publicKey)
}
```

### Multi-Algorithm Key Generation

```go
package main

import (
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rsa"
    "fmt"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA 2048-bit
    rsa2048, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)

    // Generate ECDSA P-256
    ecdsaP256, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)

    // Generate Ed25519
    ed25519Key, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)

    // All use same Manager API
    rsa2048.SaveToPEM("rsa_private.pem", "rsa_public.pem")
    ecdsaP256.SaveToPEM("ecdsa_private.pem", "ecdsa_public.pem")
    ed25519Key.SaveToPEM("ed25519_private.pem", "ed25519_public.pem")

    fmt.Println("All keys generated and saved")
}
```

### SSH Key Format

```go
package main

import (
    "crypto/ed25519"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate Ed25519 key pair
    manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)

    // Save as SSH keys with passphrase protection
    comment := "user@hostname"
    passphrase := "secure_passphrase_2024"

    manager.SaveToSSH("~/.ssh/id_ed25519", "~/.ssh/id_ed25519.pub", comment, passphrase)

    // Load SSH key
    loaded, _ := keypair.LoadFromSSH[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("~/.ssh/id_ed25519", passphrase)

    // Convert to OpenSSH authorized_keys format
    _, publicSSH, _ := loaded.ToSSH(comment, "")
    fmt.Println("Public key for authorized_keys:")
    fmt.Println(string(publicSSH))
}
```

## Security Features

### Enforced Security Standards

```go
// Minimum key sizes enforced at compile time
algo.GenerateRSAKeyPair(algo.KeySize1024) // ❌ Compile error - minimum 2048 bits
algo.GenerateRSAKeyPair(algo.KeySize2048) // ✅ Accepted

// Secure curves only
algo.GenerateECDSAKeyPair(algo.P256) // ✅ NIST P-256 curve
// Weak curves not available in API

// Strong random source
// Uses crypto/rand.Reader exclusively - no configurable random source
```

### Secure File Operations

```go
// Private keys saved with 0600 permissions (owner read/write only)
manager.SaveToPEM("private.pem", "public.pem")
// private.pem: -rw------- (0600)
// public.pem:  -rw-r--r-- (0644)

// Directories created with 0700 permissions (owner access only)
manager.SaveToPEM("keys/private.pem", "keys/public.pem")
// keys/: drwx------ (0700)
```

### Memory Safety

- No raw key material exposure in public APIs
- Type-safe interfaces prevent runtime type errors
- Defensive copying of sensitive parameters
- Zero runtime overhead from generic constraints

## Testing

### Run Tests

```bash
# All keypair module tests
go test ./keypair/...

# Manager tests only
task test:specific -- TestManager

# Algorithm-specific tests
task test:specific -- TestGenerateRSAKeyPair
task test:specific -- TestECDSAKeyPair
task test:specific -- TestEd25519KeyPair

# Format conversion tests
task test:specific -- TestToPEM
task test:specific -- TestToSSH

# SSH compatibility tests with ssh-keygen
task test:compatibility
```

### Test Coverage

**Module Coverage: 75.3%**

- `keypair.go` - Manager and core functionality
- `algo/rsa.go` - RSA implementation
- `algo/ecdsa.go` - ECDSA implementation
- `algo/ed25519.go` - Ed25519 implementation
- Format conversion functions
- File operations and validation

**Test Files:**
- `keypair_test.go` - Core Manager tests
- `algo/rsa_test.go` - Comprehensive RSA tests
- `algo/ecdsa_test.go` - ECDSA algorithm tests
- `algo/ed25519_test.go` - Ed25519 algorithm tests
- `compatibility/keypair/ssh_test.go` - OpenSSH compatibility
- `compatibility/keypair/ssh_advanced_test.go` - Advanced SSH features

## Integration with Other Modules

### With cert/ Module

```go
// Generate key pair
manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)

// Extract key pair for certificate creation
keyPair := manager.KeyPair()

// Create certificate (uses keypair types)
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{...})
```

### With signing/ Module

```go
// Use private key for document signing
privateKey := manager.PrivateKey()

// Sign document (uses keypair.PrivateKey constraint)
signature, _ := signing.SignData(document, privateKey, certificate, opts)
```

### With encryption/ Module

```go
// Use public key for encryption
publicKey := manager.PublicKey()

// Encrypt data (uses keypair.PublicKey constraint)
encrypted, _ := encryption.EncryptWithPublicKey(data, publicKey, opts)
```

### With pkcs12/ Module

```go
// Create PKCS#12 bundle with key pair
privateKey := manager.PrivateKey()

// Bundle with certificate
pkcs12.CreateP12File("bundle.p12", privateKey, certificate, caChain, opts)
```

## Best Practices

1. **Use Manager API**: Prefer `keypair.Generate()` with Manager over direct algorithm functions for consistency

2. **Type Constraints**: Always use the provided type constraints (`keypair.PrivateKey`, `keypair.PublicKey`, `keypair.KeyPair`)

3. **Secure Storage**: Use Manager's `SaveTo*()` methods for automatic secure permissions

4. **Key Sizes**: Use RSA ≥3072 bits for long-term security, 2048 for general use

5. **Algorithm Selection**:
   - **RSA**: Maximum compatibility, certificate-based workflows
   - **ECDSA**: Modern choice, smaller keys, full feature support
   - **Ed25519**: High performance signing, fast key generation

6. **Format Choice**:
   - **PEM**: Human-readable, most common, good for certificates
   - **DER**: Binary, ~30% smaller, good for performance
   - **SSH**: OpenSSH compatibility, authorized_keys format
   - **PKCS#12**: Password-protected bundles with certificates

7. **Validation**: Always validate keys after loading with `manager.Validate()`

8. **Passphrase Protection**: Use strong passphrases for SSH private keys in production

## Troubleshooting

### Common Issues

**Issue**: Compile error with generic types
```go
// ❌ Wrong: Missing type parameters
manager, _ := keypair.Generate(algo.KeySize2048)

// ✅ Correct: All type parameters specified
manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
```

**Issue**: File permission denied
```go
// Check file permissions
// Private keys should be 0600 (owner read/write only)
// Public keys should be 0644 (owner read/write, others read)
```

**Issue**: SSH key not accepted by ssh-keygen
```go
// Ensure correct SSH format
privateSSH, publicSSH, _ := manager.ToSSH("user@host", "")
// Public key should start with algorithm name (ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519)
```

## Performance Considerations

### Key Generation Performance

| Algorithm | Key Size | Time (approx) |
|-----------|----------|---------------|
| RSA | 2048-bit | ~50-100ms |
| RSA | 3072-bit | ~200-400ms |
| RSA | 4096-bit | ~1-2s |
| ECDSA | P-256 | ~5-10ms |
| ECDSA | P-384 | ~10-20ms |
| Ed25519 | 256-bit | ~1-2ms |

**Recommendation**: Ed25519 for best performance, ECDSA P-256 for balance, RSA 2048 for compatibility

### Memory Usage

- RSA keys: ~2KB (2048-bit), ~4KB (4096-bit)
- ECDSA keys: ~100 bytes (P-256), ~200 bytes (P-384)
- Ed25519 keys: ~64 bytes

**Recommendation**: ECDSA or Ed25519 for memory-constrained environments

## Further Reading

- **Architecture**: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) - Complete system design
- **Algorithms**: [`docs/ALGORITHMS.md`](../docs/ALGORITHMS.md) - Algorithm selection guide
- **Examples**: [`examples/keypair/main.go`](../examples/keypair/main.go) - Complete working examples
- **Example Docs**: [`examples/keypair/doc.md`](../examples/keypair/doc.md) - Detailed example documentation
- **Development**: [`CLAUDE.md`](../CLAUDE.md) - Development guidelines

## License

MIT License - see [LICENSE](../LICENSE) file

---

**Part of [GoPKI](../README.md) - Type-Safe Cryptography for Production**