# GoPKI

A type-safe Go library for Public Key Infrastructure (PKI) operations using generic constraints for compile-time safety.

## Features

- **Type-Safe Cryptography**: Generic constraints ensure compile-time type safety
- **Multi-Algorithm Support**: RSA, ECDSA (P-224/P-256/P-384/P-521), and Ed25519
- **Complete PKI**: Self-signed certificates, CA certificates, certificate chains
- **Production Ready**: PEM/DER formats, file operations, certificate verification

## Documentation

- **📘 [KeyPair Module](docs/KeyPair.md)** - Cryptographic key pair generation and management
- **📗 [Certificate Module](docs/Certificate.md)** - X.509 certificate creation and PKI operations

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
    keypair.KeyPairToFiles(keyPair, "private.pem", "public.pem")
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
├── examples/         # Working demonstrations
└── docs/             # Detailed module documentation
```

The library uses Go generics for type safety across all cryptographic operations.

## Examples

The `examples/` directory contains working demonstrations:

- **`examples/main.go`** - Basic key generation and certificate creation
- **`examples/certificates/`** - Advanced PKI with CA hierarchies

```bash
# Run examples
cd examples && go run main.go
cd examples/certificates && go run main.go
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
- 🚀 [Examples](examples/) - Working code demonstrations