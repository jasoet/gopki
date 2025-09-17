# GoPKI

A type-safe Go library for Public Key Infrastructure (PKI) operations using **generic constraints for compile-time safety**. This library focuses on generic abstractions and avoids `any` or `interface{}` types unless absolutely necessary, ensuring maximum type safety through Go's generic system.

## Features

- **Type-Safe Cryptography**: Pure generic interfaces with compile-time type safety
- **Multi-Algorithm Support**: RSA, ECDSA (P-224/P-256/P-384/P-521), and Ed25519
- **Complete PKI**: Self-signed certificates, CA certificates, certificate chains
- **Document Signing**: Industry-standard PKCS#7/CMS and raw signature formats
- **Data Encryption**: RFC 5652 CMS encryption with envelope encryption for large data
- **Format Support**: PEM/DER/SSH key formats with seamless conversion
- **Production Ready**: Comprehensive testing, file operations, certificate verification

## Documentation

- **📘 [KeyPair Module](docs/KeyPair.md)** - Cryptographic key pair generation and management
- **📗 [Certificate Module](docs/Certificate.md)** - X.509 certificate creation and PKI operations
- **📙 [Signing Module](docs/Signing.md)** - Document signing and signature verification
- **📔 [Encryption Module](docs/Encryption.md)** - Type-safe data encryption with CMS format support

## Installation

```bash
go get github.com/jasoet/gopki
```

## Quick Start

```go
package main

import (
    "crypto/x509/pkix"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate a key pair
    keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

    // Create a self-signed certificate
    certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "example.com"},
        DNSNames: []string{"example.com", "www.example.com"},
    })

    // Save certificate and key
    certificate.SaveToFile("certificate.pem")
    keypair.ToFiles(keyPair, "private.pem", "public.pem")
}
```

## Type-Safe API

GoPKI uses Go generics to ensure compile-time type safety:

```go
// RSA key generation
rsaKeys, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// ECDSA key generation
ecdsaKeys, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)

// Ed25519 key generation
ed25519Keys, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
```

## Architecture

```
GoPKI/
├── keypair/           # Key pair generation and management
│   ├── algo/         # Algorithm implementations (RSA, ECDSA, Ed25519)
│   └── format/       # Format conversion (PEM, DER, SSH)
├── cert/             # X.509 certificate operations
├── signing/          # Document signing and verification
│   └── formats/      # Signature formats (Raw, PKCS#7/CMS)
├── encryption/       # Type-safe data encryption with CMS format
├── examples/         # Working demonstrations
└── docs/             # Detailed module documentation
```

The library uses Go generics for type safety across all cryptographic operations with pure generic interfaces and strong type constraints.

### Document Signing Example

```go
import "github.com/jasoet/gopki/signing"

// Sign a document with RSA
signature, err := signing.SignData(document, rsaKeyPair, certificate)

// Verify signature
err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())

// Sign with PKCS#7 format
pkcs7Signature, err := signing.SignDocument(document, keyPair, certificate, signing.SignOptions{
    Format: signing.FormatPKCS7,
    HashAlgorithm: crypto.SHA256,
})
```

### Data Encryption Example

```go
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

// Type-safe decryption with automatic type inference
decrypted, err := encryption.DecodeFromCMS(cmsData, cert, privateKey)

// Using wrapper function with keypair.PrivateKey constraint
decrypted, err := encryption.DecodeDataWithKey(cmsData, cert, privateKey)
```

## Key Features

### 🔒 Data Encryption
- **Type-Safe APIs**: Pure generic interfaces with compile-time type safety
- **CMS Format**: RFC 5652 Cryptographic Message Syntax using external library
- **Multi-Algorithm**: RSA-OAEP, ECDH+AES-GCM, X25519+AES-GCM encryption
- **Envelope Encryption**: Large data encryption with multiple recipients
- **Certificate-Based**: Strongly-typed certificate encryption workflows
- **Generic Constraints**: Uses `keypair.PrivateKey` constraints for all function signatures

### 🔐 Document Signing
- **Multi-Algorithm Support**: RSA, ECDSA, Ed25519 signing
- **PKCS#7/CMS Format**: Industry-standard detached and attached signatures
- **Raw Format**: Direct signature bytes for custom applications
- **Certificate Integration**: Full X.509 certificate embedding and verification
- **Hash Algorithms**: SHA-256, SHA-384, SHA-512 support
- **Metadata Support**: Custom attributes and timestamp support

### 🔑 Key Management
- **Type-Safe Generation**: Generic constraints prevent runtime errors
- **Multiple Formats**: PEM, DER, SSH key format support
- **Format Conversion**: Seamless interchange between formats
- **File Operations**: Secure key storage with proper permissions
- **Algorithm Detection**: Automatic key type identification

### 📜 Certificate Operations
- **Self-Signed Certificates**: Quick certificate generation for development
- **CA Hierarchies**: Root CA and intermediate certificate support
- **Certificate Chains**: Complete chain building and verification
- **Extensions**: DNS names, IP addresses, email addresses, key usage
- **Verification**: Complete certificate validation including expiry and chains

## Examples

The `examples/` directory contains working demonstrations:

- **`examples/keypair/`** - Key generation, format conversion, and SSH support
- **`examples/certificates/`** - Advanced PKI with CA hierarchies and certificate chains
- **`examples/signing/`** - Document signing with multi-algorithm and PKCS#7/CMS support
- **`examples/encryption/`** - Data encryption with type-safe APIs and CMS format support

```bash
# Run examples
cd examples/keypair && go run main.go           # Key generation and format conversion
cd examples/certificates && go run main.go     # Advanced PKI operations
cd examples/signing && go run main.go          # Document signing with all algorithms
cd examples/encryption && go run main.go       # Data encryption with CMS format
```

## Development

This project uses [Task](https://taskfile.dev) for development workflows:

```bash
# Install Task
brew install go-task/tap/go-task  # macOS

# Setup project
task setup

# Run tests
task test

# Run examples
task examples:run

# View all commands
task
```

## License

MIT License - see LICENSE file for details.

---

**Learn More:**
- 📘 [KeyPair Documentation](docs/KeyPair.md) - Detailed key generation and management guide
- 📗 [Certificate Documentation](docs/Certificate.md) - Complete PKI and certificate operations guide
- 📙 [Signing Documentation](docs/Signing.md) - Document signing and PKCS#7/CMS format guide
- 📔 [Encryption Documentation](docs/Encryption.md) - Type-safe data encryption with CMS format support
- 🚀 [Examples](examples/) - Working code demonstrations