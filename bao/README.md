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
- 🔒 Full support for key rotation

### Developer Experience
- 🎯 Builder patterns for complex configurations
- 🎯 Fluent APIs for readable code with relationship navigation
- 🎯 Comprehensive error handling
- 🎯 Integration test suite with testcontainers

### Production Ready
- ⚡ Context-aware operations with timeouts
- ⚡ Proper resource cleanup
- ⚡ Extensive test coverage (80%+)
- ⚡ Compatible with OpenBao and HashiCorp Vault

---

## Architecture & Relationships

### Module Relationships

```
                     ┌──────────────────────────────────────────┐
                     │      OpenBao/Vault PKI Engine            │
                     └──────────────────────────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ↓                       ↓                       ↓
     ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
     │  KeyClient[K]   │◄───┤ IssuerClient    │───►│  RoleClient     │
     │  (Keys)         │    │ (CA Management) │    │  (Policies)     │
     └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
              │                      │                       │
              │        GetIssuers()  │  CreateRole()         │
              │                      │                       │
              │                      │  IssueXXXCertificate()│
              │                      ↓                       │
              │             ┌─────────────────────┐          │
              │             │                     │          │
              └────────────►│ CertificateClient[K]│◄─────────┘
                            │   (Certificates)    │
                            └─────────────────────┘
                    IssueCertificate()    IssueXXXCertificate()
                    
                    
Relationship Flow:
──────────────────

Forward Navigation (Creation Flow):
  Key → GetIssuers() → IssuerClient
  IssuerClient → CreateRole() → RoleClient
  IssuerClient → IssueXXXCertificate() → CertificateClient
  RoleClient → IssueXXXCertificate() → CertificateClient
  KeyClient → IssueCertificate() → CertificateClient

Reverse Navigation (Discovery Flow):
  RoleClient → GetIssuer() → IssuerClient
  IssuerClient → KeyID() → KeyClient (via GetXXXKey)
```

### Component Overview

| Component | Purpose | Key Operations | Relationships |
|-----------|---------|----------------|---------------|
| **KeyClient[K]** | Cryptographic key operations | Generate, create, import keys | → Issuers, → Certificates |
| **IssuerClient** | CA certificate management | Generate CA, import CA, configure | ← Keys, → Roles, → Certificates |
| **RoleClient** | Certificate policies | Define issuance rules, constraints | ← Issuer, → Certificates |
| **CertificateClient[K]** | End-entity certificates | Issue, retrieve, revoke | ← Key, ← Issuer, ← Role |

---

## Quick Start

### Installation

```bash
go get github.com/jasoet/gopki/bao
```

### Basic Usage

```go
import (
    "context"
    "github.com/hashicorp/vault/api"
    "github.com/jasoet/gopki/bao"
)

// 1. Create client
vaultClient, _ := api.NewClient(&api.Config{
    Address: "http://localhost:8200",
})
vaultClient.SetToken("root-token")

client := bao.NewClient(vaultClient, &bao.Config{
    Mount: "pki",
})

// 2. Generate Root CA
ctx := context.Background()
caResp, _ := client.GenerateRootCA(ctx, bao.NewRootCABuilder("My Root CA").
    WithOrganization("My Org").
    WithKeyType("rsa", 4096).
    WithTTL("87600h"). // 10 years
    Build())

// 3. Create role
issuer, _ := client.GetIssuer(ctx, caResp.IssuerID)
role, _ := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h", // 30 days
    ServerFlag:      true,
})

// 4. Generate key and issue certificate
keyClient, _ := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "web-key",
    KeyBits: 2048,
})

certClient, _ := role.IssueRSACertificate(ctx, keyClient.KeyInfo().KeyID, 
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h",
    })

fmt.Println("Certificate Serial:", certClient.CertificateInfo().SerialNumber)
```

---

## Core Concepts

### 1. Keys (KeyClient[K])

Keys are the foundation of PKI operations. OpenBao supports three key generation strategies:

```go
// Strategy 1: Generate key externally (you have the private key)
keyClient, _ := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-key",
    KeyBits: 2048,
})
keyPair, _ := keyClient.KeyPair() // ✓ Available

// Strategy 2: Create key internally (OpenBao keeps the private key)
keyClient, _ := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "secure-key",
    KeyBits: 4096,
})
keyPair, _ := keyClient.KeyPair() // ✗ Not available (managed by OpenBao)

// Strategy 3: Import existing key
localKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
keyClient, _ := client.ImportRSAKey(ctx, localKey, &bao.ImportKeyOptions{
    KeyName: "imported-key",
})
keyPair, _ := keyClient.KeyPair() // ✓ Available
```

**Key Operations:**
- `keyClient.IssueCertificate()` - Issue certificate using this key
- `keyClient.SignCSR()` - Sign a CSR with this key
- `keyClient.SignVerbatim()` - Sign CSR bypassing role constraints
- `keyClient.GetIssuers()` - Get all issuers using this key
- `keyClient.Delete()` - Delete the key
- `keyClient.UpdateName()` - Rename the key

### 2. Issuers (IssuerClient)

Issuers represent Certificate Authorities (root or intermediate):

```go
// Generate Root CA
rootCA, _ := client.GenerateRootCA(ctx, bao.NewRootCABuilder("Root CA").
    WithOrganization("My Org").
    WithCountry("US").
    WithKeyType("rsa", 4096).
    WithTTL("87600h").
    WithMaxPathLength(2).
    Build())

// Generate Intermediate CA
intermediateResp, _ := client.GenerateIntermediateCA(ctx, 
    bao.NewIntermediateCABuilder("Intermediate CA").
        WithKeyType("rsa", 2048).
        AsExported().
        Build())

// Sign intermediate with root
csrData, _ := cert.ParseCSRFromPEM([]byte(intermediateResp.CSR))
intermediateCert, _ := client.SignIntermediateCSR(ctx, csrData, &bao.CAOptions{
    CommonName:    "Intermediate CA",
    TTL:           "43800h",
    MaxPathLength: 1,
})

// Import existing CA
issuer, _ := client.ImportCA(ctx, &bao.CABundle{
    PEMBundle: caBundle,
})
```

**Issuer Operations:**
- `issuer.CreateRole()` - Create role for this issuer
- `issuer.IssueRSACertificate()` - Issue RSA certificate using this issuer
- `issuer.IssueECDSACertificate()` - Issue ECDSA certificate
- `issuer.IssueEd25519Certificate()` - Issue Ed25519 certificate
- `issuer.SignCSR()` - Sign a CSR with this issuer
- `issuer.Update()` - Update issuer configuration
- `issuer.Delete()` - Delete the issuer
- `issuer.SetAsDefault()` - Make this the default issuer

### 3. Roles (RoleClient)

Roles define policies for certificate issuance:

```go
// Create web server role
role, _ := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    AllowWildcardCertificates: true,
    TTL:             "720h",
    MaxTTL:          "8760h",
    ServerFlag:      true,
    KeyType:         "rsa",
    KeyBits:         2048,
})

// Or use builders
clientRole := bao.NewClientCertRole("internal.example.com").
    WithTTL("720h").
    EnableCodeSigning().
    Build()

client.CreateRole(ctx, "client-cert", clientRole)
```

**Role Operations:**
- `role.GetIssuer()` - Get the issuer for this role
- `role.IssueRSACertificate()` - Issue RSA certificate using this role
- `role.IssueECDSACertificate()` - Issue ECDSA certificate
- `role.IssueEd25519Certificate()` - Issue Ed25519 certificate
- `role.Update()` - Update role configuration
- `role.Delete()` - Delete the role
- `role.SetTTL()` - Update TTL
- `role.AddAllowedDomain()` - Add allowed domain

### 4. Certificates (CertificateClient[K])

Certificates are the end product of the PKI workflow:

```go
// Issue certificate (OpenBao generates key)
certClient, _ := client.GenerateRSACertificate(ctx, "web-server", 
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h",
    })

// Issue certificate (use local key)
localKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
certClient, _ := client.IssueRSACertificate(ctx, "web-server", localKey, 
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })

// Issue certificate (use OpenBao-managed key)
keyClient, _ := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{...})
certClient, _ := keyClient.IssueCertificate(ctx, "web-server", 
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })
```

**Certificate Operations:**
- `certClient.Certificate()` - Get the certificate
- `certClient.CertificateInfo()` - Get metadata
- `certClient.KeyPair()` - Get associated key pair (if available)
- `certClient.Revoke()` - Revoke the certificate

---

## API Reference

### Client Methods

#### Key Operations

```go
// Type-agnostic operations
ListKeys(ctx) ([]string, error)
GetKey(ctx, keyRef) (*KeyInfo, error)
DeleteKey(ctx, keyRef) error
UpdateKeyName(ctx, keyRef, newName) error

// RSA operations
GenerateRSAKey(ctx, opts) (*KeyClient[*algo.RSAKeyPair], error)
CreateRSAKey(ctx, opts) (*KeyClient[*algo.RSAKeyPair], error)
ImportRSAKey(ctx, kp, opts) (*KeyClient[*algo.RSAKeyPair], error)
GetRSAKey(ctx, keyRef) (*KeyClient[*algo.RSAKeyPair], error)

// ECDSA operations
GenerateECDSAKey(ctx, opts) (*KeyClient[*algo.ECDSAKeyPair], error)
CreateECDSAKey(ctx, opts) (*KeyClient[*algo.ECDSAKeyPair], error)
ImportECDSAKey(ctx, kp, opts) (*KeyClient[*algo.ECDSAKeyPair], error)
GetECDSAKey(ctx, keyRef) (*KeyClient[*algo.ECDSAKeyPair], error)

// Ed25519 operations
GenerateEd25519Key(ctx, opts) (*KeyClient[*algo.Ed25519KeyPair], error)
CreateEd25519Key(ctx, opts) (*KeyClient[*algo.Ed25519KeyPair], error)
ImportEd25519Key(ctx, kp, opts) (*KeyClient[*algo.Ed25519KeyPair], error)
GetEd25519Key(ctx, keyRef) (*KeyClient[*algo.Ed25519KeyPair], error)
```

#### Issuer Operations

```go
GenerateRootCA(ctx, opts) (*GenerateCAResponse, error)
GenerateIntermediateCA(ctx, opts) (*GenerateCAResponse, error)
SignIntermediateCSR(ctx, csr, opts) (*cert.Certificate, error)
ImportCA(ctx, bundle) (*IssuerClient, error)
GetIssuer(ctx, issuerRef) (*IssuerClient, error)
ListIssuers(ctx) ([]string, error)
DeleteIssuer(ctx, issuerRef) error
SetDefaultIssuer(ctx, issuerRef) error
GetDefaultIssuer(ctx) (string, error)
```

#### Role Operations

```go
CreateRole(ctx, name, opts) error
UpdateRole(ctx, name, opts) error
GetRole(ctx, name) (*RoleClient, error)
ListRoles(ctx) ([]string, error)
DeleteRole(ctx, name) error
```

#### Certificate Operations

```go
// Generate (OpenBao creates key)
GenerateRSACertificate(ctx, role, opts) (*CertificateClient[*algo.RSAKeyPair], error)
GenerateECDSACertificate(ctx, role, opts) (*CertificateClient[*algo.ECDSAKeyPair], error)
GenerateEd25519Certificate(ctx, role, opts) (*CertificateClient[*algo.Ed25519KeyPair], error)

// Issue (use local key)
IssueRSACertificate(ctx, role, keyPair, opts) (*CertificateClient[*algo.RSAKeyPair], error)
IssueECDSACertificate(ctx, role, keyPair, opts) (*CertificateClient[*algo.ECDSAKeyPair], error)
IssueEd25519Certificate(ctx, role, keyPair, opts) (*CertificateClient[*algo.Ed25519KeyPair], error)

// Issue with key reference (use OpenBao-managed key)
IssueRSACertificateWithKeyRef(ctx, role, keyRef, opts) (*CertificateClient[*algo.RSAKeyPair], error)
IssueECDSACertificateWithKeyRef(ctx, role, keyRef, opts) (*CertificateClient[*algo.ECDSAKeyPair], error)
IssueEd25519CertificateWithKeyRef(ctx, role, keyRef, opts) (*CertificateClient[*algo.Ed25519KeyPair], error)

// CSR operations
SignCSR(ctx, role, csr, opts) (*cert.Certificate, error)
SignVerbatim(ctx, csr, opts) (*cert.Certificate, error)
SignSelfIssued(ctx, certificate, opts) (*cert.Certificate, error)
SignCSRWithKeyRef(ctx, role, csr, keyRef, opts) (*cert.Certificate, error)
SignVerbatimWithKeyRef(ctx, csr, keyRef, opts) (*cert.Certificate, error)

// Retrieval
ListCertificates(ctx) ([]string, error)
GetCertificate(ctx, serial) (*cert.Certificate, error)
GetRSACertificate(ctx, serial) (*CertificateClient[*algo.RSAKeyPair], error)
GetECDSACertificate(ctx, serial) (*CertificateClient[*algo.ECDSAKeyPair], error)
GetEd25519Certificate(ctx, serial) (*CertificateClient[*algo.Ed25519KeyPair], error)
```

---

## Relationship-Based APIs

### Overview

The relationship-based APIs enable fluent navigation between PKI components, making complex workflows intuitive and type-safe.

### KeyClient[K] → IssuerClient

**Navigate from key to all issuers using that key:**

```go
// Get all issuers that use this key
issuers, err := keyClient.GetIssuers(ctx)
for _, issuer := range issuers {
    fmt.Printf("Issuer: %s uses key: %s\n", issuer.Name(), keyClient.KeyInfo().KeyName)
}
```

**Use case:** Key rotation - find all CAs using a key before rotating it.

### IssuerClient → RoleClient

**Create roles directly from issuer:**

```go
// Create role pre-configured with this issuer
role, err := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h",
    ServerFlag:      true,
})
// Role automatically has IssuerRef = issuer.ID()
```

**Use case:** Quickly set up roles for specific CAs.

### IssuerClient → CertificateClient[K]

**Issue certificates directly from issuer (bypassing explicit role):**

```go
// Issue RSA certificate using issuer's default role
certClient, err := issuer.IssueRSACertificate(ctx, keyRef, &bao.GenerateCertificateOptions{
    CommonName: "app.example.com",
    TTL:        "720h",
})

// Issue ECDSA certificate
ecCertClient, err := issuer.IssueECDSACertificate(ctx, keyRef, &bao.GenerateCertificateOptions{
    CommonName: "api.example.com",
    TTL:        "720h",
})

// Issue Ed25519 certificate
edCertClient, err := issuer.IssueEd25519Certificate(ctx, keyRef, &bao.GenerateCertificateOptions{
    CommonName: "service.example.com",
    TTL:        "720h",
})

// Sign CSR directly with issuer
certificate, err := issuer.SignCSR(ctx, csr, &bao.SignCertificateOptions{
    TTL: "8760h",
})
```

**Use case:** Quick certificate issuance without managing roles explicitly.

### RoleClient → IssuerClient

**Navigate from role to its issuer:**

```go
// Discover which issuer a role uses
issuer, err := role.GetIssuer(ctx)
fmt.Printf("Role '%s' uses issuer: %s\n", role.Name(), issuer.Name())
```

**Use case:** Role auditing and dependency tracking.

### RoleClient → CertificateClient[K]

**Issue certificates directly from role:**

```go
// Issue RSA certificate using this role
certClient, err := role.IssueRSACertificate(ctx, keyRef, &bao.GenerateCertificateOptions{
    CommonName: "app.example.com",
    TTL:        "720h",
})

// Issue ECDSA certificate
ecCertClient, err := role.IssueECDSACertificate(ctx, keyRef, &bao.GenerateCertificateOptions{
    CommonName: "api.example.com",
    TTL:        "720h",
})

// Issue Ed25519 certificate
edCertClient, err := role.IssueEd25519Certificate(ctx, keyRef, &bao.GenerateCertificateOptions{
    CommonName: "service.example.com",
    TTL:        "720h",
})
```

**Use case:** Certificate issuance with role-specific constraints.

### KeyClient[K] → CertificateClient[K]

**Issue certificates using a specific key:**

```go
// Key-centric workflow
keyClient, _ := client.GetRSAKey(ctx, "my-key")
certClient, err := keyClient.IssueCertificate(ctx, "web-server", &bao.GenerateCertificateOptions{
    CommonName: "app.example.com",
    TTL:        "720h",
})
```

**Use case:** Certificate issuance with specific key requirements.

### Complete Fluent Workflow Example

```go
// Create CA and get its key
caResp, _ := client.GenerateRootCA(ctx, &bao.CAOptions{
    Type:       "internal",
    CommonName: "My CA",
    KeyName:    "ca-key",
    TTL:        "87600h",
    KeyType:    "rsa",
    KeyBits:    4096,
})

// Get key → Navigate to issuers
keyClient, _ := client.GetRSAKey(ctx, caResp.KeyID)
issuers, _ := keyClient.GetIssuers(ctx)
issuer := issuers[0]

// Issuer → Create role
role, _ := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h",
    ServerFlag:      true,
})

// Role → Issue certificate
certClient, _ := role.IssueRSACertificate(ctx, keyClient.KeyInfo().KeyID, 
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })

// Reverse navigation: Role → Issuer
retrievedIssuer, _ := role.GetIssuer(ctx)
fmt.Printf("Certificate issued by: %s\n", retrievedIssuer.Name())
```

---

## Complete Examples

### Example 1: Root CA with Certificate Issuance

```go
ctx := context.Background()

// 1. Create Root CA
caResp, err := client.GenerateRootCA(ctx, bao.NewRootCABuilder("My Root CA").
    WithOrganization("My Organization").
    WithCountry("US").
    WithKeyType("rsa", 4096).
    WithTTL("87600h").
    Build())
if err != nil {
    log.Fatal(err)
}

// 2. Get issuer and create role
issuer, _ := client.GetIssuer(ctx, caResp.IssuerID)
role, _ := issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
    AllowedDomains:  []string{"example.com"},
    AllowSubdomains: true,
    TTL:             "720h",
    ServerFlag:      true,
})

// 3. Generate key and issue certificate
keyClient, _ := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "web-key",
    KeyBits: 2048,
})

certClient, _ := role.IssueRSACertificate(ctx, keyClient.KeyInfo().KeyID,
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h",
    })

fmt.Println("Certificate Serial:", certClient.CertificateInfo().SerialNumber)
```

### Example 2: Local Key with CSR Workflow

```go
// 1. Setup CA and role
caResp, _ := client.GenerateRootCA(ctx, bao.NewRootCABuilder("My CA").
    WithKeyType("rsa", 4096).
    WithTTL("87600h").
    Build())

issuer, _ := client.GetIssuer(ctx, caResp.IssuerID)
role, _ := issuer.CreateRole(ctx, "secure-client", &bao.RoleOptions{
    AllowAnyName: true,
    ClientFlag:   true,
    TTL:          "720h",
})

// 2. Generate key locally (never sent to OpenBao)
localKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// 3. Create CSR
csr, _ := cert.CreateCSR(localKey, cert.CSRRequest{
    Subject: pkix.Name{
        CommonName:   "client.example.com",
        Organization: []string{"My Org"},
        Country:      []string{"US"},
    },
})

// 4. Sign CSR with issuer
signedCert, _ := issuer.SignCSR(ctx, csr, &bao.SignCertificateOptions{
    TTL: "720h",
})

// Private key stays local, only certificate from OpenBao
fmt.Println("Certificate:", signedCert.Certificate.Subject.CommonName)
```

### Example 3: Key Rotation Workflow

```go
// 1. Find all issuers using old key
oldKey, _ := client.GetRSAKey(ctx, "old-key-id")
issuers, _ := oldKey.GetIssuers(ctx)

// 2. Generate new key
newKey, _ := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "new-key",
    KeyBits: 4096,
})

// 3. For each issuer, update or create new issuer with new key
for _, issuer := range issuers {
    fmt.Printf("Issuer '%s' uses old key\n", issuer.Name())
    // Generate new issuer or update configuration
}

// 4. After migration, delete old key
oldKey.Delete(ctx)
```

### Example 4: Multi-Issuer Environment

```go
// Production issuer
prodCA, _ := client.GenerateRootCA(ctx, bao.NewRootCABuilder("Production CA").
    WithKeyType("rsa", 4096).
    WithIssuerName("prod-ca").
    WithTTL("87600h").
    Build())

// Development issuer
devCA, _ := client.GenerateRootCA(ctx, bao.NewRootCABuilder("Development CA").
    WithKeyType("rsa", 2048).
    WithIssuerName("dev-ca").
    WithTTL("8760h").
    Build())

// Get issuer clients
prodIssuer, _ := client.GetIssuer(ctx, prodCA.IssuerID)
devIssuer, _ := client.GetIssuer(ctx, devCA.IssuerID)

// Create environment-specific roles
prodRole, _ := prodIssuer.CreateRole(ctx, "prod-web", &bao.RoleOptions{
    AllowedDomains: []string{"example.com"},
    TTL:            "720h",
    ServerFlag:     true,
})

devRole, _ := devIssuer.CreateRole(ctx, "dev-web", &bao.RoleOptions{
    AllowedDomains: []string{"dev.example.com"},
    TTL:            "168h", // 7 days
    ServerFlag:     true,
})

// Issue certificates from different environments
prodCert, _ := prodRole.IssueRSACertificate(ctx, "prod-key", 
    &bao.GenerateCertificateOptions{
        CommonName: "api.example.com",
        TTL:        "720h",
    })

devCert, _ := devRole.IssueRSACertificate(ctx, "dev-key",
    &bao.GenerateCertificateOptions{
        CommonName: "api.dev.example.com",
        TTL:        "168h",
    })
```

---

## Testing

### Unit Tests

```bash
go test ./bao
```

### Integration Tests

Integration tests use testcontainers to spin up OpenBao:

```bash
go test -v -tags=integration ./bao
```

**Test Coverage:**
- Key generation and management (all types)
- CA generation (root and intermediate)
- Role creation and configuration
- Certificate issuance (multiple workflows)
- Relationship navigation (all directions)
- Certificate revocation
- Error handling

### Test Container Helper

The package provides a test container helper:

```go
//go:build integration

import "github.com/jasoet/gopki/bao/testcontainer"

// Setup OpenBao container
container, err := testcontainer.StartOpenBao(ctx, &testcontainer.Options{
    Version: "2.4.3",
    Token:   "test-token",
})
defer testcontainer.StopOpenBao(ctx, container)

// Get client
client := testcontainer.GetClient(container)
```

---

## Best Practices

### Security

1. **Keep private keys local when possible**
   ```go
   // Use CSR workflow for sensitive keys
   localKey, _ := algo.GenerateRSAKeyPair(algo.KeySize4096)
   csr, _ := cert.CreateCSR(localKey, csrReq)
   signedCert, _ := issuer.SignCSR(ctx, csr, opts)
   // Private key never sent to OpenBao
   ```

2. **Use appropriate key sizes**
   ```go
   // Production: RSA 4096 or ECDSA P-384
   keyClient, _ := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
       KeyBits: 4096,
   })
   ```

3. **Set reasonable TTLs**
   ```go
   // Different TTLs for different use cases
   serverRole := &bao.RoleOptions{
       TTL:    "720h",  // 30 days for servers
       MaxTTL: "8760h", // 1 year max
   }
   clientRole := &bao.RoleOptions{
       TTL:    "168h",  // 7 days for clients
       MaxTTL: "720h",  // 30 days max
   }
   ```

### Error Handling

```go
// Always check errors
certClient, err := role.IssueRSACertificate(ctx, keyRef, opts)
if err != nil {
    if strings.Contains(err.Error(), "key name already in use") {
        // Handle duplicate key name
    } else if strings.Contains(err.Error(), "role not found") {
        // Handle missing role
    }
    return fmt.Errorf("certificate issuance failed: %w", err)
}
```

### Resource Cleanup

```go
// Use defer for cleanup
keyClient, err := client.GenerateRSAKey(ctx, opts)
if err != nil {
    return err
}
defer keyClient.Delete(ctx)

// Cleanup roles after testing
role, _ := issuer.CreateRole(ctx, "test-role", opts)
defer client.DeleteRole(ctx, "test-role")
```

### Context Timeouts

```go
// Set appropriate timeouts
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

certClient, err := role.IssueRSACertificate(ctx, keyRef, opts)
if err != nil {
    return fmt.Errorf("operation timeout: %w", err)
}
```

### Relationship Navigation

```go
// Use relationship APIs for cleaner code
issuer, _ := client.GetIssuer(ctx, issuerID)
role, _ := issuer.CreateRole(ctx, "web", opts)
cert, _ := role.IssueRSACertificate(ctx, keyRef, certOpts)

// Instead of:
client.CreateRole(ctx, "web", &bao.RoleOptions{IssuerRef: issuerID, ...})
role, _ := client.GetRole(ctx, "web")
cert, _ := client.IssueRSACertificateWithKeyRef(ctx, "web", keyRef, certOpts)
```

---

## License

Part of the GoPKI project. See main repository for license information.

---

## Related Documentation

- [Main GoPKI README](../README.md)
- [Architecture Overview](../docs/ARCHITECTURE.md)
- [Algorithm Guide](../docs/ALGORITHMS.md)
- [Examples](../examples/)

---

**Need help?** Check the integration tests for comprehensive usage examples!
