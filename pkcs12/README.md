# pkcs12/ - PKCS#12 File Management

**PKCS#12 file operations for bundling private keys with certificates.**

[![Test Coverage](https://img.shields.io/badge/Coverage-79.1%25-green.svg)](https://github.com/jasoet/gopki)

## Overview

PKCS#12 (P12/PFX) file management with support for:
- **Multi-algorithm keys** (RSA, ECDSA, Ed25519)
- **Certificate chain bundling**
- **Password protection**
- **Cross-platform compatibility** (Windows, macOS, Linux)
- **Integration with keypair and cert modules**

## 🤖 AI Agent Quick Start

### File Structure

```
pkcs12/
├── pkcs12.go              [Core PKCS#12 operations]
├── pkcs12_test.go         [Comprehensive tests]
└── pkcs12_simple_test.go  [Simple workflow tests]
```

### Key Functions

| Function | Purpose |
|----------|---------|
| `CreateP12File()` | Create PKCS#12 file with options |
| `QuickCreateP12()` | Simple P12 creation |
| `LoadFromP12File()` | Load P12 file with validation |
| `QuickLoadP12()` | Simple P12 loading |

### Common Tasks

**Creating P12 bundle:**
1. Generate key pair with `keypair.Generate()`
2. Create certificate with `cert.CreateSelfSignedCertificate()`
3. Bundle with `pkcs12.CreateP12File()`
4. Load with `pkcs12.LoadFromP12File()`

### Dependencies

- **keypair/** - Key types for P12 bundling
- **cert/** - Certificate bundling
- **software.sslmate.com/src/go-pkcs12** - PKCS#12 library

## Quick Start

```go
import (
    "github.com/jasoet/gopki/pkcs12"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/cert"
)

// Generate key pair and certificate
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{...})

// Create P12 file
opts := pkcs12.CreateOptions{
    Password:     "secure_password_2024",
    FriendlyName: "My Certificate",
    Iterations:   8192,  // High security
}
err := pkcs12.CreateP12File("certificate.p12", keyPair.PrivateKey, certificate.Certificate, nil, opts)

// Load P12 file
container, _ := pkcs12.LoadFromP12File("certificate.p12", pkcs12.LoadOptions{
    Password: "secure_password_2024",
})

// Extract contents
privateKey := container.PrivateKey
cert := container.Certificate
chain := container.CertificateChain
```

## API Reference

### Creation Functions

```go
// Advanced P12 creation
func CreateP12File(filename string, privateKey interface{}, cert *x509.Certificate, chain []*x509.Certificate, opts CreateOptions) error

// Simple P12 creation
func QuickCreateP12(filename, password string, privateKey interface{}, cert *x509.Certificate) error
```

### Loading Functions

```go
// Advanced P12 loading with validation
func LoadFromP12File(filename string, opts LoadOptions) (*Container, error)

// Simple P12 loading
func QuickLoadP12(filename, password string) (*Container, error)
```

### Options

```go
type CreateOptions struct {
    Password     string  // PKCS#12 password
    FriendlyName string  // Human-readable name
    Iterations   int     // Key derivation iterations (2048-16384)
}

type LoadOptions struct {
    Password         string                // PKCS#12 password
    TrustedCerts     []*x509.Certificate  // Trusted CA certificates
    SkipVerification bool                 // Skip certificate chain verification
}
```

### Container Operations

```go
type Container struct {
    PrivateKey       interface{}           // Private key (any algorithm)
    Certificate      *x509.Certificate     // Primary certificate
    CertificateChain []*x509.Certificate   // Certificate chain
    FriendlyName     string                // Human-readable name
}

// Container methods
func (c *Container) GetKeyType() string
func (c *Container) ExtractCertificateChain() []*x509.Certificate
func (c *Container) Validate() error
```

## Security Levels

| Use Case | Iterations | Security Level |
|----------|-----------|----------------|
| **Development** | 2048 | Basic |
| **Production** | 4096-8192 | Standard |
| **High Security** | 16384+ | Maximum |

## Real-World Scenarios

### Web Server Certificate

```go
opts := pkcs12.CreateOptions{
    Password:     "webserver_password",
    FriendlyName: "Production Web Server",
    Iterations:   8192,
}
pkcs12.CreateP12File("webserver.p12", serverKey, serverCert, caChain, opts)
```

### Client Authentication

```go
pkcs12.QuickCreateP12("client_auth.p12", "client_password", clientKey, clientCert)
```

### Code Signing Certificate

```go
opts := pkcs12.CreateOptions{
    Password:     "codesign_password",
    FriendlyName: "Software Publisher Certificate",
    Iterations:   16384,  // Maximum security
}
pkcs12.CreateP12File("codesign.p12", codeSignKey, codeSignCert, nil, opts)
```

## Testing

```bash
# Run PKCS#12 tests
go test ./pkcs12/...

# Specific tests
task test:specific -- TestCreateP12File
task test:specific -- TestLoadFromP12File
task test:specific -- TestQuickP12Workflow
```

**Test Coverage:** 79.1%

## Best Practices

1. **Strong Passwords**: Use 16+ character passwords
2. **High Iterations**: Use ≥8192 for production
3. **Include Certificate Chain**: Bundle complete CA hierarchy
4. **Friendly Names**: Use descriptive names for identification
5. **Secure Storage**: Protect P12 files with file system permissions
6. **Validate After Loading**: Always call `container.Validate()`

## Cross-Platform Compatibility

PKCS#12 files created by GoPKI work with:
- ✅ **Windows**: Import into certificate store
- ✅ **macOS**: Import into Keychain
- ✅ **Linux**: Use with OpenSSL tools
- ✅ **Browsers**: Firefox, Chrome, Safari, Edge
- ✅ **Java**: Keytool and Java keystores

## Further Reading

- **Examples**: [`examples/pkcs12/main.go`](../examples/pkcs12/main.go)
- **Example Docs**: [`examples/pkcs12/doc.md`](../examples/pkcs12/doc.md)
- **Architecture**: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)

---

**Part of [GoPKI](../README.md) - Type-Safe Cryptography for Production**