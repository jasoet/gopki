# cert/ - X.509 Certificate Management

**Certificate creation, CA operations, and certificate chain management.**

[![Test Coverage](https://img.shields.io/badge/Coverage-74.3%25-green.svg)](https://github.com/jasoet/gopki)

## Overview

X.509 certificate operations with support for:
- **Self-signed certificates**
- **CA certificate hierarchies**
- **Certificate signing** (intermediate and end-entity)
- **Certificate chain verification**
- **Subject Alternative Names** (DNS, IP, Email)
- **OpenSSL certificate compatibility** (100%)

## 🤖 AI Agent Quick Start

### File Structure

```
cert/
├── cert.go          [Certificate creation and management]
├── ca.go            [Certificate Authority operations]
├── cert_test.go     [Certificate tests]
└── ca_test.go       [CA operation tests]
```

### Key Functions

| Function | Purpose |
|----------|---------|
| `CreateSelfSignedCertificate()` | Create self-signed certificate |
| `CreateCACertificate()` | Create CA certificate with constraints |
| `SignCertificate()` | Sign certificate with CA |
| `VerifyCertificate()` | Verify certificate chain |

### Common Tasks

**Creating CA Hierarchy:**
1. Create root CA with `CreateCACertificate()`
2. Create intermediate CA signed by root
3. Create end-entity certificate signed by intermediate
4. Verify chain with `VerifyCertificate()`

### Dependencies

- **keypair/** - Key pairs for certificate operations
- **crypto/x509** - Standard library X.509 support

## Quick Start

```go
import (
    "crypto/x509/pkix"
    "time"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

// Create CA certificate
caKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize4096)
caCert, _ := cert.CreateCACertificate(caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "My Root CA"},
    ValidFor: 10 * 365 * 24 * time.Hour,
    IsCA: true,
    MaxPathLen: 2,
})

// Create server certificate signed by CA
serverKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
serverCert, _ := cert.SignCertificate(caCert, caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "server.example.com"},
    DNSNames: []string{"server.example.com", "www.example.com"},
    IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
    ValidFor: 365 * 24 * time.Hour,
}, serverKeys.PublicKey)

// Verify certificate chain
err := cert.VerifyCertificate(serverCert, caCert)
```

## API Reference

### Certificate Creation

```go
// Self-signed certificate
func CreateSelfSignedCertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error)

// CA certificate
func CreateCACertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error)

// Sign certificate with CA
func SignCertificate[T keypair.KeyPair](caCert *Certificate, caKeyPair T, request CertificateRequest, publicKey crypto.PublicKey) (*Certificate, error)
```

### Certificate Verification

```go
// Verify certificate against CA
func VerifyCertificate(cert *Certificate, caCert *Certificate) error

// Verify certificate chain
func VerifyCertificateChain(cert *Certificate, intermediates []*Certificate, roots []*Certificate) error
```

### Certificate Request

```go
type CertificateRequest struct {
    Subject      pkix.Name        // Certificate subject
    DNSNames     []string         // DNS SANs
    IPAddresses  []net.IP         // IP SANs
    EmailAddress []string         // Email SANs
    ValidFrom    time.Time        // Start time
    ValidFor     time.Duration    // Validity period
    IsCA         bool            // CA certificate flag
    MaxPathLen   int             // CA path length constraint
}
```

## CA Features

### Path Length Constraints

```go
// Root CA with path length 2
caCert, _ := cert.CreateCACertificate(rootKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "Root CA"},
    IsCA: true,
    MaxPathLen: 2,  // Allows 2 intermediate CAs
    ValidFor: 20 * 365 * 24 * time.Hour,
})
```

### Subject Alternative Names

```go
serverCert, _ := cert.SignCertificate(caCert, caKeys, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "server.example.com"},
    DNSNames: []string{
        "server.example.com",
        "www.server.example.com",
        "*.api.example.com",  // Wildcard supported
    },
    IPAddresses: []net.IP{
        net.IPv4(192, 168, 1, 10),
        net.ParseIP("2001:db8::1"),  // IPv6 supported
    },
    EmailAddress: []string{"admin@example.com"},
}, serverKeys.PublicKey)
```

## Testing

```bash
# Run certificate tests
go test ./cert/...

# Specific tests
task test:specific -- TestCreateSelfSignedCertificate
task test:specific -- TestCACertificate
task test:specific -- TestSignCertificate

# OpenSSL compatibility
task test:compatibility
```

**Test Coverage:** 74.3%

## Best Practices

1. **Use Strong Keys**: RSA ≥3072 for CAs, ≥2048 for end-entity
2. **Set Appropriate Validity**: Long for CAs (10-20 years), short for servers (1-2 years)
3. **Path Length Constraints**: Limit intermediate CA depth
4. **Subject Alternative Names**: Always include for web servers
5. **Certificate Chains**: Keep full chain for verification

## Further Reading

- **Examples**: [`examples/certificates/main.go`](../examples/certificates/main.go)
- **Example Docs**: [`examples/certificates/doc.md`](../examples/certificates/doc.md)
- **OpenSSL Compatibility**: [`docs/OPENSSL_COMPAT.md`](../docs/OPENSSL_COMPAT.md)
- **Architecture**: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)

---

**Part of [GoPKI](../README.md) - Type-Safe Cryptography for Production**