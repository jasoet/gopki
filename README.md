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
├── keypair/           # Key pair generation and management
│   ├── keypair.go     # Generic interfaces and core functions
│   └── algo/          # Algorithm-specific implementations
│       ├── rsa.go     # RSA key pair operations
│       ├── ecdsa.go   # ECDSA key pair operations
│       └── ed25519.go # Ed25519 key pair operations
├── cert/              # Certificate operations
│   ├── certificate.go # Certificate creation and management
│   └── certificate_test.go
├── examples/          # Working examples
└── docs/              # Documentation
    ├── KeyPair.md     # KeyPair module documentation
    ├── Certificate.md # Certificate module documentation
    └── README.md      # This file
```

## Common Use Cases

### 🌐 TLS/SSL Certificates
```go
// Generate key pair
keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// Create server certificate
cert, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "www.example.com"},
    DNSNames: []string{"www.example.com", "example.com"},
    IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
})
```

### 🏛️ Certificate Authority
```go
// Create root CA
rootCA, _ := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
    Subject: pkix.Name{
        Organization: []string{"Example Corp"},
        CommonName:   "Example Root CA",
    },
    MaxPathLen: 2, // Can create 2 levels of intermediate CAs
})

// Sign server certificate
serverCert, _ := cert.SignCertificate(rootCA, caKeyPair, request, serverPublicKey)
```

### 🔗 Certificate Chains
```go
// Root CA → Intermediate CA → Server Certificate
rootCA := createRootCA()
intermediateCA := signIntermediateCA(rootCA, intermediateRequest)
serverCert := signServerCert(intermediateCA, serverRequest)

// Verify the complete chain
cert.VerifyCertificate(serverCert, intermediateCA)
cert.VerifyCertificate(intermediateCA, rootCA)
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

The `examples/` directory contains working demonstrations:

- **basic_unified/**: Simple key generation and certificate creation
- **generic_wrapper/**: Advanced generic usage patterns  
- **certificates/**: Certificate-specific examples

Run any example:
```bash
cd examples/basic_unified
go run main.go
```

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