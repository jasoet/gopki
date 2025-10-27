# OpenBao/Vault PKI Integration

**Type-safe PKI operations with OpenBao and HashiCorp Vault**

[![Go Version](https://img.shields.io/badge/Go-1.24.5+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Test Coverage](https://img.shields.io/badge/coverage-80%25-brightgreen)](.)
[![Integration Tests](https://img.shields.io/badge/integration-passing-success)](.)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture & Relationships](#architecture--relationships)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
  - [KeyClient](#keyclient)
  - [IssuerClient](#issuerclient)
  - [RoleClient](#roleclient)
  - [CertificateClient](#certificateclient)
- [API Reference](#api-reference)
- [Relationship-Based APIs](#relationship-based-apis)
- [Complete Examples](#complete-examples)
- [Testing](#testing)

---

## Overview

The `bao` package provides seamless integration between GoPKI's type-safe cryptographic operations and OpenBao/Vault PKI secrets engine. It enables centralized certificate authority management while maintaining the security and type safety that GoPKI is known for.

### What You Can Do

- **Manage Certificate Authorities**: Create root and intermediate CAs
- **Generate Keys**: RSA, ECDSA, and Ed25519 with type-safe operations
- **Issue Certificates**: Multiple workflows for different security requirements
- **Configure Policies**: Role-based certificate issuance policies
- **Navigate Relationships**: Fluent APIs between Keys, Issuers, Roles, and Certificates
- **Complete Lifecycle**: From CA setup to certificate revocation

---

## Key Features

### Type-Safe Design
- ✅ Generic-based API prevents runtime type errors
- ✅ Compile-time type checking for all cryptographic operations
- ✅ Support for RSA, ECDSA, and Ed25519 algorithms

### Security First
- 🔒 Private keys can stay local (never sent to OpenBao)
- 🔒 CSR-based certificate issuance workflow
- 🔒 Secure key storage in OpenBao when needed

### Integration Features
- 🔗 Fluent APIs for navigating between related resources
- 🔗 Builder patterns for complex configurations
- 🔗 Automatic relationship management

### Developer Experience
- 📚 Comprehensive documentation and examples
- 🧪 Integration tests with testcontainers
- 🎯 Clear error messages and type safety
- 🚀 Simple and intuitive API design

---

## Architecture & Relationships

The `bao` package is built around four core types that have clear relationships with each other:

```
┌─────────────────┐
│  KeyClient[K]   │  ← Foundation: Manages cryptographic keys
└────────┬────────┘
         │ GetIssuers()
         ↓
┌─────────────────┐
│  IssuerClient   │  ← Certificate Authority: Signs certificates
└────────┬────────┘
         │ CreateRole() / IssueXXXCertificate()
         ↓
┌─────────────────┐
│   RoleClient    │  ← Policy: Defines certificate constraints
└────────┬────────┘
         │ GetIssuer() / IssueXXXCertificate()
         ↓
┌─────────────────┐
│CertificateClient│  ← End Result: Issued certificate
└─────────────────┘
```

### Relationship Flow

1. **KeyClient → IssuerClient**: A key becomes an issuer when it's used to create a CA certificate
2. **IssuerClient → RoleClient**: Issuers can create roles to define certificate policies
3. **RoleClient → CertificateClient**: Roles are used to issue certificates with specific constraints
4. **Bidirectional Navigation**: All relationships support navigation in both directions

### Key Relationships

| From | To | Method | Description |
|------|------|--------|-------------|
| KeyClient | IssuerClient | `GetIssuers()` | Find all CAs using this key |
| IssuerClient | RoleClient | `CreateRole()` | Create a role under this CA |
| IssuerClient | CertificateClient | `IssueXXXCertificate()` | Issue certificate directly |
| RoleClient | IssuerClient | `GetIssuer()` | Get the CA for this role |
| RoleClient | CertificateClient | `IssueXXXCertificate()` | Issue certificate using role |

---

## Quick Start

### Installation

```bash
go get github.com/jasoet/gopki/bao
```

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/jasoet/gopki/bao"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    ctx := context.Background()
    
    // 1. Connect to OpenBao
    client, err := bao.NewClient(&bao.Config{
        Address: "http://localhost:8200",
        Token:   "root-token",
        Mount:   "pki",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // 2. Generate CA key and certificate
    caKey, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
        KeyName: "my-ca-key",
        KeyBits: 4096,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // 3. Create CA (issuer)
    caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
        Type:       "internal",
        CommonName: "My Root CA",
        KeyType:    "rsa",
        KeyBits:    4096,
        KeyName:    "my-ca-key",
        IssuerName: "my-ca",
        TTL:        "87600h", // 10 years
    })
    if err != nil {
        log.Fatal(err)
    }
    
    issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
    if err != nil {
        log.Fatal(err)
    }
    
    // 4. Create a role using the issuer
    role, err := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
        AllowedDomains:  []string{"example.com"},
        AllowSubdomains: true,
        TTL:             "720h",
        ServerFlag:      true,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // 5. Issue a certificate using the role
    certClient, err := role.IssueRSACertificate(ctx, "my-app-key", 
        &bao.GenerateCertificateOptions{
            CommonName: "app.example.com",
            TTL:        "720h",
        })
    if err != nil {
        log.Fatal(err)
    }
    
    cert := certClient.Certificate()
    fmt.Printf("Certificate issued: %s\n", cert.Subject.CommonName)
}
```

---

## Core Concepts

### KeyClient

`KeyClient[K]` provides type-safe operations for cryptographic keys stored in OpenBao.

**Type Parameters:**
- `K`: Key pair type (`*algo.RSAKeyPair`, `*algo.ECDSAKeyPair`, or `*algo.Ed25519KeyPair`)

**Key Features:**
- Generate keys in OpenBao (internal) or export key material
- Import existing keys
- Type-safe operations prevent mixing incompatible key types
- Navigate to issuers using this key

**Example:**
```go
// Generate RSA key (key stays in OpenBao)
keyClient, err := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-key",
    KeyBits: 2048,
})

// Export RSA key (returns key material)
keyClient, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-exported-key",
    KeyBits: 2048,
})
keyPair, err := keyClient.KeyPair() // Get the key material

// Find all issuers using this key
issuers, err := keyClient.GetIssuers(ctx)
```

### IssuerClient

`IssuerClient` represents a Certificate Authority (CA) that can sign certificates.

**Key Features:**
- Manage CA certificates (root and intermediate)
- Create roles for certificate issuance
- Issue certificates directly
- Sign CSRs
- Update CA configuration

**Example:**
```go
// Get issuer
issuer, err := client.GetIssuer(ctx, "my-ca")

// Create a role under this issuer
role, err := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h",
})

// Issue certificate directly from issuer
certClient, err := issuer.IssueRSACertificate(ctx, "my-key", 
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
    })

// Sign a CSR
cert, err := issuer.SignCSR(ctx, csr, &bao.SignCertificateOptions{
    TTL: "720h",
})
```

### RoleClient

`RoleClient` defines policies and constraints for certificate issuance.

**Key Features:**
- Configure allowed domains, SANs, key types, etc.
- Link to specific issuer
- Issue certificates with role constraints
- Update role configuration with builder pattern

**Example:**
```go
// Get role
role, err := client.GetRole(ctx, "web-server")

// Get the issuer for this role
issuer, err := role.GetIssuer(ctx)

// Issue certificate using role
certClient, err := role.IssueRSACertificate(ctx, "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })

// Update role with builder pattern
err = role.Update(ctx, 
    bao.NewRoleOptionsBuilder().
        WithTTL("1440h").
        WithAllowedDomains("example.com", "example.org").
        WithServerFlag(true).
        Build())
```

### CertificateClient

`CertificateClient[K]` represents an issued certificate with optional key material.

**Type Parameters:**
- `K`: Key pair type (same as KeyClient)

**Key Features:**
- Access certificate and metadata
- Revoke certificates
- Access key pair if available (when generated/imported)
- Type-safe certificate and key operations

**Example:**
```go
// Issue certificate
certClient, err := role.IssueRSACertificate(ctx, "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
    })

// Access certificate
cert := certClient.Certificate()
fmt.Printf("CN: %s\n", cert.Subject.CommonName)

// Access key pair (if available)
if certClient.HasKeyPair() {
    keyPair, err := certClient.KeyPair()
    // Use keyPair for signing, encryption, etc.
}

// Revoke certificate
err = certClient.Revoke(ctx)
```

---

## API Reference

### Client Creation

```go
// Create client
client, err := bao.NewClient(&bao.Config{
    Address: "http://localhost:8200",
    Token:   "root-token",
    Mount:   "pki",
})
```

### Key Operations

#### Generate Keys (Internal - OpenBao stores private key)
```go
keyClient, err := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-key",
    KeyBits: 2048,
})

keyClient, err := client.CreateECDSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-ec-key",
    KeyBits: 256,
})

keyClient, err := client.CreateEd25519Key(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-ed25519-key",
})
```

#### Generate Keys (Exported - Returns private key)
```go
keyClient, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-exported-key",
    KeyBits: 2048,
})
keyPair, err := keyClient.KeyPair() // Get key material
```

#### Import Keys
```go
rsaKeyPair, _ := algo.GenerateRSAKeyPair(2048)
keyClient, err := client.ImportRSAKey(ctx, rsaKeyPair, 
    &bao.ImportKeyOptions{
        KeyName: "imported-key",
    })
```

#### Key Operations
```go
// List keys
keys, err := client.ListKeys(ctx)

// Get key metadata
keyInfo, err := client.GetKey(ctx, "key-id")

// Get typed key client
keyClient, err := client.GetRSAKey(ctx, "my-key")

// Find issuers using this key
issuers, err := keyClient.GetIssuers(ctx)

// Delete key
err := client.DeleteKey(ctx, "key-id")
```

### Issuer Operations

#### Create CA
```go
// Root CA
caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
    Type:       "internal",
    CommonName: "My Root CA",
    KeyType:    "rsa",
    KeyBits:    4096,
    KeyName:    "my-ca-key",
    IssuerName: "my-ca",
    TTL:        "87600h",
})

// Intermediate CA
intermediateResp, err := client.GenerateIntermediateCA(ctx, &bao.CAOptions{
    Type:       "exported",
    CommonName: "My Intermediate CA",
    KeyType:    "rsa",
    KeyBits:    2048,
    IssuerName: "my-intermediate",
    TTL:        "43800h",
})
```

#### Issuer Operations
```go
// List issuers
issuers, err := client.ListIssuers(ctx)

// Get issuer
issuer, err := client.GetIssuer(ctx, "issuer-id")

// Set default issuer
err := issuer.SetAsDefault(ctx)

// Update issuer
err := issuer.UpdateName(ctx, "new-name")
err := issuer.UpdateUsage(ctx, "read-only,issuing-certificates")

// Create role under issuer
role, err := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains: []string{"example.com"},
    TTL:            "720h",
})

// Issue certificate from issuer
certClient, err := issuer.IssueRSACertificate(ctx, "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
    })

// Sign CSR
cert, err := issuer.SignCSR(ctx, csr, &bao.SignCertificateOptions{
    TTL: "720h",
})

// Delete issuer
err := issuer.Delete(ctx)
```

### Role Operations

#### Create and Manage Roles
```go
// Create role
err := client.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h",
    MaxTTL:          "8760h",
    ServerFlag:      true,
})

// Get role
role, err := client.GetRole(ctx, "web-server")

// List roles
roles, err := client.ListRoles(ctx)

// Update role using builder
err = role.Update(ctx, 
    bao.NewRoleOptionsBuilder().
        WithTTL("1440h").
        WithAllowedDomains("example.com", "example.org").
        WithServerFlag(true).
        WithClientFlag(true).
        Build())

// Delete role
err := role.Delete(ctx)
```

#### Role Navigation
```go
// Get issuer for this role
issuer, err := role.GetIssuer(ctx)

// Issue certificate using role
certClient, err := role.IssueRSACertificate(ctx, "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })
```

### Certificate Operations

#### Issue Certificates
```go
// Using role (with existing key)
certClient, err := client.IssueRSACertificateWithKeyRef(ctx, "web-server", "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.example.com"},
        TTL:        "720h",
    })

// Generate new key and certificate together
certClient, err := client.GenerateRSACertificate(ctx, "web-server",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })
```

#### Sign CSR
```go
// Create CSR locally
rsaKeyPair, _ := algo.GenerateRSAKeyPair(2048)
csr, _ := cert.CreateCSR(rsaKeyPair, cert.CSRRequest{
    Subject: cert.SubjectInfo{
        CommonName: "app.example.com",
    },
})

// Sign with OpenBao
certificate, err := client.SignCSR(ctx, "web-server", csr,
    &bao.SignCertificateOptions{
        TTL: "720h",
    })
```

#### Certificate Operations
```go
// Get certificate
certClient, err := client.GetRSACertificate(ctx, "serial-number")

// Access certificate
cert := certClient.Certificate()
certInfo := certClient.CertificateInfo()

// Access key pair (if available)
if certClient.HasKeyPair() {
    keyPair, err := certClient.KeyPair()
}

// Revoke certificate
err := certClient.Revoke(ctx)
```

---

## Relationship-Based APIs

The `bao` package provides fluent APIs for navigating between related resources:

### From Key to Issuers

```go
// Find all CAs using a specific key
keyClient, _ := client.GetRSAKey(ctx, "my-key")
issuers, err := keyClient.GetIssuers(ctx)

for _, issuer := range issuers {
    fmt.Printf("Issuer: %s (ID: %s)\n", issuer.Name(), issuer.ID())
}
```

### From Issuer to Roles and Certificates

```go
issuer, _ := client.GetIssuer(ctx, "my-ca")

// Create role under this issuer
role, err := issuer.CreateRole(ctx, "api-server", &bao.RoleOptions{
    AllowedDomains: []string{"api.example.com"},
    TTL:            "720h",
})

// Issue certificate directly from issuer
certClient, err := issuer.IssueRSACertificate(ctx, "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "api.example.com",
    })
```

### From Role to Issuer and Certificates

```go
role, _ := client.GetRole(ctx, "web-server")

// Get the issuer for this role
issuer, err := role.GetIssuer(ctx)
fmt.Printf("Role uses issuer: %s\n", issuer.Name())

// Issue certificate using role
certClient, err := role.IssueRSACertificate(ctx, "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
    })
```

### Complete Workflow Example

```go
// 1. Start with a key
keyClient, _ := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-ca-key",
    KeyBits: 4096,
})

// 2. Create CA using that key
caResp, _ := client.GenerateRootCA(ctx, &bao.CAOptions{
    Type:       "internal",
    CommonName: "My CA",
    KeyName:    "my-ca-key",
    IssuerName: "my-ca",
})

// 3. Get issuer and create role
issuer, _ := client.GetIssuer(ctx, caResp.IssuerID)
role, _ := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains: []string{"example.com"},
    TTL:            "720h",
})

// 4. Issue certificate using role
certClient, _ := role.IssueRSACertificate(ctx, "app-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
    })

// 5. Navigate back
roleIssuer, _ := role.GetIssuer(ctx)
keyIssuers, _ := keyClient.GetIssuers(ctx)

fmt.Printf("Role's issuer: %s\n", roleIssuer.Name())
fmt.Printf("Key is used by %d issuer(s)\n", len(keyIssuers))
```

---

## Complete Examples

### Example 1: Simple CA Setup

```go
ctx := context.Background()

// Connect
client, _ := bao.NewClient(&bao.Config{
    Address: "http://localhost:8200",
    Token:   "root-token",
    Mount:   "pki",
})

// Generate CA
caResp, _ := client.GenerateRootCA(ctx, &bao.CAOptions{
    Type:       "internal",
    CommonName: "My Root CA",
    KeyType:    "rsa",
    KeyBits:    4096,
    IssuerName: "root-ca",
    TTL:        "87600h",
})

fmt.Printf("CA Created: %s\n", caResp.Certificate.Subject.CommonName)
```

### Example 2: Certificate Issuance with Role

```go
ctx := context.Background()
client, _ := bao.NewClient(&bao.Config{...})

// Create role
err := client.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h",
    ServerFlag:      true,
})

// Issue certificate
certClient, _ := client.IssueRSACertificateWithKeyRef(ctx, "web-server", "my-key",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.example.com", "api.example.com"},
        TTL:        "720h",
    })

cert := certClient.Certificate()
fmt.Printf("Certificate issued: %s\n", cert.Subject.CommonName)
```

### Example 3: CSR-Based Workflow (Maximum Security)

```go
ctx := context.Background()
client, _ := bao.NewClient(&bao.Config{...})

// 1. Generate key locally (never leaves your system)
rsaKeyPair, _ := algo.GenerateRSAKeyPair(2048)

// 2. Create CSR locally
csr, _ := cert.CreateCSR(rsaKeyPair, cert.CSRRequest{
    Subject: cert.SubjectInfo{
        CommonName:   "app.example.com",
        Organization: []string{"My Company"},
    },
    DNSNames: []string{"www.example.com"},
})

// 3. Sign CSR with OpenBao (only CSR is sent, not private key)
certificate, _ := client.SignCSR(ctx, "web-server", csr,
    &bao.SignCertificateOptions{
        TTL: "720h",
    })

fmt.Printf("Certificate signed: %s\n", certificate.Subject.CommonName)
// Private key never left your system!
```

### Example 4: Relationship Navigation

```go
ctx := context.Background()
client, _ := bao.NewClient(&bao.Config{...})

// Start with a role
role, _ := client.GetRole(ctx, "web-server")

// Navigate to issuer
issuer, _ := role.GetIssuer(ctx)
fmt.Printf("Role uses issuer: %s\n", issuer.Name())

// Get key info
keyID := issuer.KeyID()
fmt.Printf("Issuer uses key: %s\n", keyID)

// Get key and find all its issuers
keyClient, _ := client.GetRSAKey(ctx, keyID)
issuers, _ := keyClient.GetIssuers(ctx)
fmt.Printf("Key is used by %d issuer(s)\n", len(issuers))
```

---

## Testing

### Unit Tests

```bash
go test ./bao -v
```

### Integration Tests

Integration tests use testcontainers to spin up a real OpenBao instance:

```bash
go test ./bao -tags=integration -v
```

### Cross-Module Integration Tests

Tests that verify relationship navigation and complex workflows:

```bash
go test ./bao -tags=integration -run TestCrossModule -v
```

### Writing Tests

Example integration test:

```go
func TestMyFeature(t *testing.T) {
    // Setup OpenBao container
    ctx := context.Background()
    baoContainer, err := testcontainer.SetupOpenBao(ctx)
    require.NoError(t, err)
    defer testcontainer.TeardownOpenBao(ctx, baoContainer)
    
    // Get client
    client := baoContainer.Client
    
    // Your test code here
    keyClient, err := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
        KeyName: "test-key",
        KeyBits: 2048,
    })
    require.NoError(t, err)
    assert.NotNil(t, keyClient)
}
```

---

## Advanced Topics

### Builder Pattern for Roles

Use `RoleOptionsBuilder` for complex role configurations:

```go
opts := bao.NewRoleOptionsBuilder().
    WithIssuerRef("my-ca").
    WithTTL("720h").
    WithMaxTTL("8760h").
    WithAllowedDomains("example.com", "example.org").
    WithAllowSubdomains(true).
    WithAllowWildcardCertificates(true).
    WithServerFlag(true).
    WithClientFlag(true).
    WithKeyType("rsa").
    WithKeyBits(2048).
    WithOrganization("My Company").
    WithCountry("US").
    Build()

err := client.CreateRole(ctx, "my-role", opts)
```

### Error Handling

The package provides helper functions for error classification:

```go
cert, err := client.GetRSACertificate(ctx, "serial")
if err != nil {
    if bao.IsNotFoundError(err) {
        fmt.Println("Certificate not found")
    } else if bao.IsAuthError(err) {
        fmt.Println("Authentication failed")
    } else if bao.IsRetryable(err) {
        fmt.Println("Temporary error, retry later")
    } else {
        fmt.Printf("Other error: %v\n", err)
    }
}
```

### Type Safety Benefits

The generic-based API prevents common mistakes:

```go
// Compile-time error: can't mix RSA and ECDSA
rsaKey, _ := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{...})
ecdsaCert, _ := client.IssueECDSACertificate(ctx, ...) // Different types

// This works: types match
rsaKey, _ := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{...})
rsaCert, _ := client.IssueRSACertificate(ctx, ...)
keyPair, _ := rsaCert.KeyPair() // Returns *algo.RSAKeyPair
```

---

## Best Practices

1. **Use CSR Workflow for Maximum Security**: Keep private keys local, only send CSRs to OpenBao
2. **Leverage Relationships**: Use fluent APIs to navigate between related resources
3. **Use Roles for Policies**: Define certificate constraints in roles, not in each request
4. **Type Safety**: Use typed methods (`IssueRSACertificate`) over generic ones
5. **Error Handling**: Use helper functions (`IsNotFoundError`, etc.) for robust error handling
6. **Builder Pattern**: Use `RoleOptionsBuilder` for complex role configurations
7. **Integration Tests**: Use testcontainers for reliable integration testing

---

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Integration tests are included for new features
- Documentation is updated
- Code follows existing patterns

---

## License

See LICENSE file in the repository root.
