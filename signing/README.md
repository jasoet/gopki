# GoPKI Document Signing Module

The signing module provides comprehensive document signing and signature verification functionality using certificates and various cryptographic algorithms.

## Features

- **Multi-Algorithm Support**: RSA, ECDSA (P-256/P-384/P-521), and Ed25519
- **Type-Safe Design**: Uses Go generics for compile-time safety
- **Flexible Formats**: Raw signatures with planned PKCS#7/CMS support
- **Certificate Integration**: Works seamlessly with the GoPKI cert module
- **Streaming Support**: Handle large documents efficiently
- **Verification**: Complete signature verification with certificate validation

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
    // Generate key pair
    keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }

    // Create certificate
    certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Document Signer"},
        ValidFor: 365 * 24 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Sign document
    document := []byte("Important document content")
    signature, err := signing.SignData(document, keyPair, certificate)
    if err != nil {
        log.Fatal(err)
    }

    // Verify signature
    err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Document signed and verified successfully!")
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

🔄 **Planned Features**
- PKCS#7/CMS format support
- Timestamp authority integration
- PDF signing support
- S/MIME email signing

## Integration

The signing module integrates seamlessly with other GoPKI modules:

- Uses `keypair` module for key generation
- Uses `cert` module for certificate operations
- Maintains the same type-safe generic design patterns

For more information, see the main GoPKI documentation and the examples directory.