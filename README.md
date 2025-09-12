# GoPKI Documentation

A comprehensive Go library for Public Key Infrastructure (PKI) operations with type-safe generic interfaces.

## Documentation Index

### 📘 [KeyPair Module](docs/KeyPair.md)
**Cryptographic key pair generation and management**

- **Theory**: RSA, ECDSA, Ed25519 cryptographic algorithms
- **Type Safety**: Generic interfaces with compile-time validation
- **Features**: Key generation, PEM conversion, file operations, algorithm detection
- **Tutorial**: Step-by-step examples from basic to advanced usage

### 📗 [Certificate Module](docs/Certificate.md)  
**X.509 certificate creation and management**

- **Theory**: PKI fundamentals, certificate types, trust models
- **Features**: Self-signed certificates, CA certificates, certificate chains
- **Advanced**: Intermediate CAs, path length constraints, certificate verification
- **Tutorial**: Complete examples from simple certificates to complex PKI hierarchies

## Quick Start

### Installation
```bash
go get github.com/jasoet/gopki
```

### Basic Example
```go
package main

import (
    "crypto/x509/pkix"
    "fmt"
    "log"
    
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // 1. Generate a key pair
    keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }
    
    // 2. Create a self-signed certificate
    certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{
            CommonName: "example.com",
        },
        DNSNames: []string{"example.com", "www.example.com"},
    })
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Certificate created for: %s\n", certificate.Certificate.Subject.CommonName)
    
    // 3. Save certificate and key
    certificate.SaveToFile("certificate.pem")
    keypair.KeyPairToFiles(keyPair, "private.pem", "public.pem")
    
    fmt.Println("Files saved: certificate.pem, private.pem, public.pem")
}
```

## Key Features

### 🔐 Type-Safe Cryptography
- **Generic Constraints**: Compile-time type safety for all cryptographic operations
- **Multi-Algorithm**: Support for RSA, ECDSA (P-224/P-256/P-384/P-521), and Ed25519
- **Unified Interface**: Single API for all supported algorithms

### 📜 Complete PKI Support
- **Certificate Types**: Self-signed, CA certificates, intermediate CAs, end-entity certificates
- **Certificate Chains**: Multi-level hierarchies with path length controls
- **Standards Compliant**: Full X.509 certificate support with proper key usage

### 💾 Production Ready
- **File Operations**: Secure key and certificate storage with proper permissions
- **PEM Format**: Standard PEM encoding/decoding
- **Validation**: Built-in certificate verification and chain validation

## Architecture

```
GoPKI
├── keypair/                    # Key pair generation and management
│   ├── keypair.go             # Generic interfaces and core functions
│   ├── keypair_test.go        # KeyPair module tests
│   ├── certificate.go         # Certificate wrapper functions
│   ├── certificate_test.go    # Certificate tests
│   ├── compatibility_test.go  # Cross-compatibility tests
│   ├── error_handling_test.go # Error handling tests
│   ├── file_io_test.go        # File I/O operation tests
│   ├── generic_parsing_test.go # Generic parsing tests
│   └── algo/                  # Algorithm-specific implementations
│       ├── rsa.go            # RSA key pair operations
│       ├── ecdsa.go          # ECDSA key pair operations
│       └── ed25519.go        # Ed25519 key pair operations
├── cert/                      # Certificate operations
│   ├── certificate.go        # Certificate creation and management
│   └── certificate_test.go   # Certificate module tests
├── utils/                     # Utility functions
│   ├── pem.go                # PEM encoding/decoding utilities
│   └── file_ops_test.go      # File operations tests
├── examples/                  # Working examples
│   ├── main.go               # Basic usage example
│   ├── certificates/         # Certificate-specific examples
│   │   └── main.go
│   └── generic_parsing_example.go # Generic parsing demonstration
├── docs/                      # Documentation
│   ├── KeyPair.md            # KeyPair module documentation
│   └── Certificate.md        # Certificate module documentation
├── go.mod                     # Go module definition
└── README.md                  # This file
```

## Common Use Cases

### 🔑 **1. Multi-Algorithm Key Generation**
Generate keys with compile-time type safety:
```go
// RSA key pair
rsaKeys, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// ECDSA key pair  
ecdsaKeys, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)

// Ed25519 key pair
ed25519Keys, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")

// Save all to files with proper permissions
keypair.ToFiles(rsaKeys, "rsa_private.pem", "rsa_public.pem")
```

### 🌐 **2. TLS/SSL Certificates** 
Create production-ready certificates:
```go
// Generate key pair
keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// Create server certificate with SAN
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "www.example.com"},
    DNSNames: []string{"www.example.com", "example.com", "api.example.com"},
    IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
    ValidFor: 365 * 24 * time.Hour, // 1 year
})

// Save certificate and keys
certificate.SaveToFile("server.pem")
keypair.ToFiles(keyPair, "server-key.pem", "server-pub.pem")
```

### 🏛️ **3. Certificate Authority Setup**
Build complete PKI infrastructure:
```go
// Root CA with path length constraints
rootCA, _ := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
    Subject: pkix.Name{
        Organization: []string{"Example Corp"},
        CommonName:   "Example Root CA",
    },
    MaxPathLen: 2, // Allow 2 levels of intermediate CAs
    ValidFor: 10 * 365 * 24 * time.Hour, // 10 years
})

// Sign intermediate CA
intermediateCA, _ := cert.SignCertificate(rootCA, caKeyPair, intermediateRequest, intermediatePubKey)

// Sign end-entity certificate
serverCert, _ := cert.SignCertificate(intermediateCA, intermediateKeyPair, serverRequest, serverPubKey)
```

### 🔍 **4. Algorithm Detection & Parsing**
Parse keys without knowing the algorithm:
```go
pemData, _ := os.ReadFile("unknown-key.pem")

// Auto-detect and parse
if key, algorithm, err := keypair.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
    fmt.Printf("Detected %s key, size: %d bits\n", algorithm, key.Size()*8)
} else if key, algorithm, err := keypair.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
    fmt.Printf("Detected %s key, curve: %s\n", algorithm, key.Curve.Params().Name)
} else if key, algorithm, err := keypair.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
    fmt.Printf("Detected %s key, length: %d bytes\n", algorithm, len(key))
}
```

## Algorithm Comparison

| Algorithm | Key Size | Security Level | Performance | Use Case |
|-----------|----------|----------------|-------------|----------|
| **RSA** | 2048-4096 bit | High (with adequate key size) | Slower | Legacy compatibility, general purpose |
| **ECDSA P-256** | 256 bit | ~3072-bit RSA equivalent | Fast | Modern TLS, certificates |
| **ECDSA P-384** | 384 bit | ~7680-bit RSA equivalent | Fast | High security applications |
| **Ed25519** | 256 bit | ~3072-bit RSA equivalent | Fastest | Modern applications, SSH keys |

## Best Practices

### 🔒 Security
- **Key Sizes**: Use 2048+ bit RSA, P-256+ ECDSA, or Ed25519
- **Validity Periods**: 1-2 years for end-entity, 3-10 years for CAs
- **Storage**: Keep private keys secure, use HSMs for production CAs

### ⚡ Performance  
- **Algorithm Choice**: Ed25519 for best performance, ECDSA P-256 for balanced security/performance
- **Key Reuse**: Generate keys once and reuse appropriately
- **Chain Depth**: Minimize certificate chain length

### 🛠️ Development
- **Error Handling**: Always check and handle errors appropriately
- **Type Safety**: Use generic functions for compile-time validation
- **Testing**: Verify certificate properties and validation logic

## Examples Directory

The `examples/` directory contains focused working demonstrations:

### 🔑 **main.go** - Basic Key Operations
Demonstrates all three cryptographic algorithms and basic certificate creation:
- RSA key generation (2048-bit)
- ECDSA key generation (P-256 curve)  
- Ed25519 key generation
- Self-signed certificate creation
- Algorithm detection from PEM files

**Generated files**: `output/*.pem` (keys and certificates)

### 📜 **certificates/** - Advanced Certificate Operations
Complete PKI examples with CA hierarchies:
- Root CA certificate creation
- Server certificate signing with CA
- Self-signed certificate generation
- Certificate chain verification
- Multiple algorithm usage (RSA for CA, ECDSA for end-entity)

**Generated files**: `certificates/certs/*.pem` (complete PKI setup)

### 🚀 **Running Examples**

```bash
# Basic key operations and certificate creation
cd examples
go run main.go

# Advanced PKI and certificate operations
cd examples/certificates
go run main.go
```

Both examples generate working PEM files that you can use with standard tools like OpenSSL.

## Contributing

1. Read the module documentation to understand the architecture
2. Follow the existing patterns for type safety and error handling
3. Include comprehensive tests for new functionality
4. Update documentation for any API changes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Need Help?** 
- 📖 Read the detailed [KeyPair](docs/KeyPair.md) and [Certificate](docs/Certificate.md) documentation
- 🚀 Try the examples in the `examples/` directory
- 🐛 Report issues or request features on GitHub