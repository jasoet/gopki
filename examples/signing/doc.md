# Signing Module

Document signing and signature verification with multi-algorithm support and certificate integration.

> 📖 **Related Documentation**: [KeyPair Module](KeyPair.md) | [Certificate Module](Certificate.md) | [Main README](../README.md)

## Features

- **Multi-Algorithm Support**: All algorithms from [KeyPair Module](KeyPair.md) - RSA, ECDSA (P-256/P-384/P-521), and Ed25519
- **Type-Safe Design**: Uses Go generics for compile-time safety, consistent with other modules
- **Certificate Integration**: Works seamlessly with [Certificate Module](Certificate.md) certificates
- **Signature Formats**: Raw signatures and complete PKCS#7/CMS support (industry standard)
- **Streaming Support**: Efficient signing of large documents via `io.Reader`
- **Complete Verification**: Full signature verification with certificate chain validation
- **Metadata Support**: Include custom attributes and certificate chains in signatures

## Quick Start

```go
package main

import (
    "crypto/x509/pkix"
    "fmt"
    "log"
    "time"

    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/signing"
)

func main() {
    // 1. Generate key pair (see KeyPair Module docs)
    keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }

    // 2. Create certificate (see Certificate Module docs)
    certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Document Signer"},
        ValidFor: 365 * 24 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }

    // 3. Sign document
    document := []byte("Important document content")
    signature, err := signing.SignData(document, keyPair, certificate)
    if err != nil {
        log.Fatal(err)
    }

    // 4. Verify signature
    err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("✓ Document signed and verified successfully!")
}
```

## API Overview

### Core Functions

- `SignData()` - Sign data with default options
- `SignDocument()` - Sign data with custom options
- `SignStream()` - Sign data from an io.Reader
- `VerifySignature()` - Verify a signature
- `VerifyWithCertificate()` - Verify using specific certificate

### Signature Types

- `Signature` - Contains signature data and metadata
- `SignOptions` - Configure signing behavior
- `VerifyOptions` - Configure verification behavior

### Supported Algorithms

| Algorithm | Key Sizes | Hash Algorithms | Notes |
|-----------|-----------|----------------|-------|
| RSA | 2048, 3072, 4096+ bits | SHA-256, SHA-384, SHA-512 | Industry standard |
| ECDSA | P-256, P-384, P-521 | SHA-256, SHA-384, SHA-512 | Smaller signatures |
| Ed25519 | 256-bit (fixed) | SHA-512 (internal) | Fastest performance |

## Examples

See the `examples/signing/` directory for comprehensive examples including:

- Basic document signing with all algorithms
- Advanced signing options
- Multi-party signatures (co-signing)
- Signature verification scenarios
- Certificate chain handling

## Testing

```bash
# Run all signing tests
go test ./signing -v

# Run specific test
go test ./signing -v -run TestSignAndVerifyRSA

# Test with coverage
go test ./signing -v -cover
```

## Development Status

✅ **Completed Features**
- Core signing infrastructure
- RSA, ECDSA, Ed25519 support
- Raw signature format
- Comprehensive verification
- Certificate integration
- Streaming API
- Full test coverage

✅ **Advanced Features**
- Complete PKCS#7/CMS format support (attached and detached signatures)
- Format registry for extensible signature format support
- Comprehensive test coverage for all algorithms and formats

## Integration

The signing module integrates seamlessly with other GoPKI modules:

- Uses `keypair` module for key generation
- Uses `cert` module for certificate operations
- Maintains the same type-safe generic design patterns

## Development

See the [main README](../README.md) for development commands using Taskfile.

```bash
# Run signing module tests
task test:signing          # Once implemented in Taskfile

# Run all tests including signing
task test

# Run signing examples
cd examples/signing && go run .
```

## Integration with Other Modules

The signing module integrates seamlessly with other GoPKI modules:

- **[KeyPair Module](KeyPair.md)**: Uses all supported algorithms (RSA, ECDSA, Ed25519)
- **[Certificate Module](Certificate.md)**: Works with any certificate type (self-signed, CA-signed)
- **Formats Package**: Complete signature format implementation (Raw, PKCS#7/CMS)

For comprehensive examples and detailed API documentation, see:
- Main project documentation: [README](../README.md)
- Working examples: `examples/signing/`
- Algorithm details: [KeyPair Module](KeyPair.md)
- Certificate operations: [Certificate Module](Certificate.md)

---

> 📖 **Related Documentation**: [KeyPair Module](KeyPair.md) | [Certificate Module](Certificate.md) | [Main README](../README.md)