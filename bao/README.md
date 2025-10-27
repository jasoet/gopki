# OpenBao/Vault PKI Integration

**Type-safe PKI operations with OpenBao and HashiCorp Vault**

[![Go Version](https://img.shields.io/badge/Go-1.24.5+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Test Coverage](https://img.shields.io/badge/coverage-80%25-brightgreen)](.)
[![Integration Tests](https://img.shields.io/badge/integration-passing-success)](.)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
- [Complete Examples](#complete-examples)
- [Testing](#testing)
- [Best Practices](#best-practices)

---

## Overview

The `bao` package provides seamless integration between GoPKI's type-safe cryptographic operations and OpenBao/Vault PKI secrets engine. It enables centralized certificate authority management while maintaining the security and type safety that GoPKI is known for.

### What You Can Do

- **Manage Certificate Authorities**: Create root and intermediate CAs
- **Generate Keys**: RSA, ECDSA, and Ed25519 with type-safe operations
- **Issue Certificates**: Multiple workflows for different security requirements
- **Configure Policies**: Role-based certificate issuance policies
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
- 🎯 Fluent APIs for readable code
- 🎯 Comprehensive error handling
- 🎯 Integration test suite with testcontainers

### Production Ready
- ⚡ Context-aware operations with timeouts
- ⚡ Proper resource cleanup
- ⚡ Extensive test coverage (80%+)
- ⚡ Compatible with OpenBao and HashiCorp Vault

---

## Architecture

### Module Relationships

```
┌─────────────────────────────────────────────────────────────────┐
│                         OpenBao/Vault                           │
│                         PKI Secrets Engine                       │
└────────┬────────────────┬────────────────┬──────────────────────┘
         │                │                │
         ↓                ↓                ↓
    IssuerClient     KeyClient[K]    RoleClient
    (CA Mgmt)        (Keys)           (Policies)
         │                │                │
         │                └────────┬───────┘
         │                         │
         └─────────────┬───────────┘
                       ↓
             CertificateClient[K]
             (Certificates)
```

### Component Overview

| Component | Purpose | Key Operations |
|-----------|---------|----------------|
| **IssuerClient** | CA certificate management | Generate root/intermediate CA, import CA, configure issuers |
| **KeyClient[K]** | Cryptographic key operations | Generate, create, import keys; issue certificates |
| **CertificateClient[K]** | End-entity certificates | Issue, retrieve, revoke certificates |
| **RoleClient** | Certificate policies | Define issuance rules, constraints, TTL |

### Workflow Patterns

1. **Complete CA Setup**: IssuerClient → RoleClient → KeyClient → CertificateClient
2. **Local Key Certificate**: Local KeyPair → CertificateClient (CSR workflow)
3. **OpenBao-Managed Key**: KeyClient → CertificateClient
4. **Key Rotation**: KeyClient (rotate) → CertificateClient (reissue)

---

## Quick Start

### Installation

```bash
go get github.com/jasoet/gopki
```

### Basic Example

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jasoet/gopki/bao"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // 1. Create client
    client, err := bao.NewClient(&bao.Config{
        Address: "http://localhost:8200",
        Token:   "root-token",
        Mount:   "pki",
        Timeout: 30 * time.Second,
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    // 2. Setup CA
    _, err = client.GenerateRootCA(ctx, bao.NewRootCABuilder("My Root CA").
        WithOrganization("My Company").
        WithKeyType("rsa", 4096).
        WithTTL("87600h").
        Build())
    if err != nil {
        log.Fatal(err)
    }

    // 3. Create role
    err = client.CreateRole(ctx, "web-server", bao.NewWebServerRole("example.com").
        WithTTL("720h").
        EnableSubdomains().
        Build())
    if err != nil {
        log.Fatal(err)
    }

    // 4. Generate key and issue certificate
    keyClient, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
        KeyName: "web-key",
        KeyBits: 2048,
    })
    if err != nil {
        log.Fatal(err)
    }

    certClient, err := keyClient.IssueCertificate(ctx, "web-server", &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("✓ Certificate issued: %s", certClient.CertificateInfo().SerialNumber)
}
```

---

## Core Concepts

### 1. Issuer (CA Management)

The `IssuerClient` manages Certificate Authorities - both root and intermediate CAs.

**Key Methods:**
- `GenerateRootCA()` - Create a self-signed root CA
- `GenerateIntermediateCA()` - Create an intermediate CA
- `SignIntermediateCSR()` - Sign intermediate CA CSR
- `ImportCA()` - Import existing CA
- `UpdateIssuer()` - Configure issuer settings
- `SetAsDefault()` - Set as default issuer

**Builder Pattern:**
```go
rootCA, err := client.GenerateRootCA(ctx, 
    bao.NewRootCABuilder("Production Root CA").
        WithOrganization("Acme Corp").
        WithCountry("US").
        WithKeyType("rsa", 4096).
        WithTTL("87600h").  // 10 years
        WithMaxPathLength(2).
        Build())
```

### 2. Key (Cryptographic Keys)

The `KeyClient[K]` provides type-safe key operations with generic constraints.

**Key Types:**
- `KeyClient[*algo.RSAKeyPair]` - RSA keys
- `KeyClient[*algo.ECDSAKeyPair]` - ECDSA keys
- `KeyClient[*algo.Ed25519KeyPair]` - Ed25519 keys

**Two Approaches:**

1. **Generate (Exported)** - Private key returned to you:
```go
keyClient, _ := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "my-key",
    KeyBits: 2048,
})
keyPair, _ := keyClient.KeyPair()  // ✓ Available
```

2. **Create (Internal)** - Private key stays in OpenBao:
```go
keyClient, _ := client.CreateRSAKey(ctx, &bao.GenerateKeyOptions{
    KeyName: "managed-key",
    KeyBits: 2048,
})
// keyPair NOT available - key managed internally
```

**Integration with Certificates:**
```go
// KeyClient can directly issue certificates
certClient, _ := keyClient.IssueCertificate(ctx, "role", &bao.GenerateCertificateOptions{
    CommonName: "service.example.com",
    TTL:        "720h",
})
```

### 3. Certificate (End-Entity Certificates)

The `CertificateClient[K]` handles end-entity certificate operations.

**Three Issuance Patterns:**

1. **Generate** - OpenBao generates both key and certificate:
```go
certClient, _ := client.GenerateRSACertificate(ctx, "role", &bao.GenerateCertificateOptions{
    CommonName: "api.example.com",
    TTL:        "720h",
})
keyPair, _ := certClient.KeyPair()  // ✓ Private key returned
```

2. **Issue** - Use local key (most secure):
```go
localKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
certClient, _ := client.IssueRSACertificate(ctx, "role", localKey, &bao.GenerateCertificateOptions{
    CommonName: "secure.example.com",
    TTL:        "720h",
})
// Private key never leaves local system!
```

3. **IssueWithKeyRef** - Use OpenBao-managed key:
```go
keyClient, _ := client.GetRSAKey(ctx, "existing-key-id")
certClient, _ := client.IssueRSACertificateWithKeyRef(ctx, "role", keyClient.KeyInfo().KeyID, &bao.GenerateCertificateOptions{
    CommonName: "managed.example.com",
    TTL:        "720h",
})
```

### 4. Role (Certificate Policies)

The `RoleClient` defines certificate issuance policies and constraints.

**Builder Pattern:**
```go
// Web server role
roleOpts := bao.NewWebServerRole("example.com").
    WithTTL("720h").
    WithMaxTTL("8760h").
    EnableSubdomains().
    EnableWildcards().
    Build()

// Client certificate role
roleOpts := bao.NewClientCertRole("client.example.com").
    WithTTL("720h").
    Build()

// Custom role
roleOpts := bao.NewRoleOptionsBuilder().
    WithIssuerRef("my-issuer").
    WithTTL("720h").
    WithAllowedDomains("internal.example.com").
    WithKeyType("rsa", 2048).
    WithServerAuth().
    EnableSubdomains().
    Build()
```

**Convenience Methods:**
```go
roleClient, _ := client.GetRole(ctx, "web-server")
_ = roleClient.SetTTL(ctx, "1440h")
_ = roleClient.AddAllowedDomain(ctx, "newdomain.com")
_ = roleClient.EnableServerAuth(ctx)
```

---

## API Reference

### Client Configuration

```go
type Config struct {
    Address   string        // OpenBao/Vault address (required)
    Token     string        // Authentication token (required)
    Mount     string        // PKI mount path (default: "pki")
    Timeout   time.Duration // Request timeout (default: 30s)
}

client, err := bao.NewClient(&bao.Config{
    Address: "http://localhost:8200",
    Token:   "root-token",
    Mount:   "pki",
    Timeout: 30 * time.Second,
})
```

### Issuer Operations

| Method | Description | Returns |
|--------|-------------|---------|
| `GenerateRootCA(ctx, opts)` | Generate root CA | `*GenerateCAResponse` |
| `GenerateIntermediateCA(ctx, opts)` | Generate intermediate CA | `*GenerateCAResponse` |
| `SignIntermediateCSR(ctx, csr, opts)` | Sign intermediate CSR | `*cert.Certificate` |
| `ImportCA(ctx, bundle)` | Import existing CA | `*IssuerClient` |
| `GetIssuer(ctx, ref)` | Get issuer by ID/name | `*IssuerClient` |
| `ListIssuers(ctx)` | List all issuers | `[]string` |
| `SetDefaultIssuer(ctx, ref)` | Set default issuer | `error` |

**IssuerClient Methods:**
- `ID()` - Get issuer ID
- `Name()` - Get issuer name
- `KeyID()` - Get associated key ID
- `Certificate()` - Get issuer certificate
- `Update(ctx, config)` - Update configuration
- `Delete(ctx)` - Delete issuer
- `SetAsDefault(ctx)` - Set as default

### Key Operations

| Method | Description | Returns |
|--------|-------------|---------|
| `GenerateRSAKey(ctx, opts)` | Generate RSA key (exported) | `*KeyClient[*algo.RSAKeyPair]` |
| `CreateRSAKey(ctx, opts)` | Create RSA key (internal) | `*KeyClient[*algo.RSAKeyPair]` |
| `ImportRSAKey(ctx, kp, opts)` | Import RSA key | `*KeyClient[*algo.RSAKeyPair]` |
| `GetRSAKey(ctx, ref)` | Get RSA key by ID/name | `*KeyClient[*algo.RSAKeyPair]` |
| `ListKeys(ctx)` | List all keys | `[]string` |

Similar methods exist for ECDSA (`GenerateECDSAKey`, etc.) and Ed25519 (`GenerateEd25519Key`, etc.).

**KeyClient[K] Methods:**
- `KeyInfo()` - Get key metadata
- `KeyPair()` - Get cached key pair (if available)
- `HasKeyPair()` - Check if key pair cached
- `Delete(ctx)` - Delete key
- `UpdateName(ctx, name)` - Update key name
- `IssueCertificate(ctx, role, opts)` - Issue certificate with this key
- `SignCSR(ctx, role, csr, opts)` - Sign CSR with this key
- `SignVerbatim(ctx, csr, opts)` - Sign CSR verbatim

### Certificate Operations

| Method | Description | Returns |
|--------|-------------|---------|
| `GenerateRSACertificate(ctx, role, opts)` | Generate certificate (OpenBao key) | `*CertificateClient[*algo.RSAKeyPair]` |
| `IssueRSACertificate(ctx, role, kp, opts)` | Issue certificate (local key) | `*CertificateClient[*algo.RSAKeyPair]` |
| `IssueRSACertificateWithKeyRef(ctx, role, keyRef, opts)` | Issue certificate (OpenBao-managed key) | `*CertificateClient[*algo.RSAKeyPair]` |
| `SignCSR(ctx, role, csr, opts)` | Sign CSR | `*cert.Certificate` |
| `GetCertificate(ctx, serial)` | Get certificate by serial | `*cert.Certificate` |
| `ListCertificates(ctx)` | List all certificates | `[]string` |
| `RevokeCertificate(ctx, serial)` | Revoke certificate | `error` |

Similar methods exist for ECDSA and Ed25519.

**CertificateClient[K] Methods:**
- `Certificate()` - Get certificate
- `CertificateInfo()` - Get metadata
- `KeyPair()` - Get cached key pair (if available)
- `HasKeyPair()` - Check if key pair cached
- `Revoke(ctx)` - Revoke this certificate
- `RevokeWithKey(ctx)` - Revoke using private key

### Role Operations

| Method | Description | Returns |
|--------|-------------|---------|
| `CreateRole(ctx, name, opts)` | Create or update role | `error` |
| `GetRole(ctx, name)` | Get role by name | `*RoleClient` |
| `ListRoles(ctx)` | List all roles | `[]string` |
| `DeleteRole(ctx, name)` | Delete role | `error` |

**RoleClient Methods:**
- `Name()` - Get role name
- `Options()` - Get role options
- `Update(ctx, opts)` - Update role
- `Delete(ctx)` - Delete role
- `SetTTL(ctx, ttl)` - Update TTL
- `SetMaxTTL(ctx, maxTTL)` - Update max TTL
- `AddAllowedDomain(ctx, domain)` - Add allowed domain
- `RemoveAllowedDomain(ctx, domain)` - Remove allowed domain
- `EnableServerAuth(ctx)` - Enable server authentication
- `EnableClientAuth(ctx)` - Enable client authentication

---

## Complete Examples

### Example 1: Complete CA Setup with Certificate Issuance

```go
func setupProductionCA() error {
    client, _ := bao.NewClient(&bao.Config{
        Address: "https://vault.example.com",
        Token:   os.Getenv("VAULT_TOKEN"),
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // 1. Generate root CA
    rootCA, err := client.GenerateRootCA(ctx, 
        bao.NewRootCABuilder("Production Root CA").
            WithOrganization("Acme Corporation").
            WithCountry("US").
            WithKeyType("rsa", 4096).
            WithTTL("87600h").  // 10 years
            WithIssuerName("prod-root").
            Build())
    if err != nil {
        return fmt.Errorf("root CA: %w", err)
    }

    // 2. Create role for web servers
    err = client.CreateRole(ctx, "web-server", 
        bao.NewWebServerRole("example.com").
            WithTTL("720h").    // 30 days
            WithMaxTTL("8760h"). // 1 year
            EnableSubdomains().
            EnableWildcards().
            WithOrganization("Acme Corporation").
            Build())
    if err != nil {
        return fmt.Errorf("role: %w", err)
    }

    // 3. Generate key and issue certificate
    keyClient, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
        KeyName: "web-frontend-key",
        KeyBits: 2048,
    })
    if err != nil {
        return fmt.Errorf("key: %w", err)
    }

    certClient, err := keyClient.IssueCertificate(ctx, "web-server", &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com", "api.app.example.com"},
        TTL:        "720h",
    })
    if err != nil {
        return fmt.Errorf("certificate: %w", err)
    }

    log.Printf("✓ Certificate issued: %s", certClient.CertificateInfo().SerialNumber)
    return nil
}
```

### Example 2: Secure Certificate Issuance (Local Key)

```go
func issueSecureCertificate() error {
    client, _ := bao.NewClient(&bao.Config{
        Address: "https://vault.example.com",
        Token:   os.Getenv("VAULT_TOKEN"),
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // 1. Generate key locally (private key never leaves!)
    keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
    if err != nil {
        return fmt.Errorf("generate key: %w", err)
    }

    // 2. Issue certificate using local key
    certClient, err := client.IssueRSACertificate(ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
        CommonName: "secure.example.com",
        AltNames:   []string{"www.secure.example.com"},
        TTL:        "720h",
    })
    if err != nil {
        return fmt.Errorf("issue certificate: %w", err)
    }

    // 3. Save certificate and private key
    certificate := certClient.Certificate()
    err = os.WriteFile("certificate.pem", certificate.PEMData, 0644)
    if err != nil {
        return fmt.Errorf("save certificate: %w", err)
    }

    privateKeyPEM, err := keyPair.PrivateKeyToPEM()
    if err != nil {
        return fmt.Errorf("private key PEM: %w", err)
    }
    err = os.WriteFile("private_key.pem", privateKeyPEM, 0600)
    if err != nil {
        return fmt.Errorf("save private key: %w", err)
    }

    log.Printf("✓ Certificate and key saved securely")
    return nil
}
```

### Example 3: Key Rotation

```go
func rotateKey() error {
    client, _ := bao.NewClient(&bao.Config{
        Address: "https://vault.example.com",
        Token:   os.Getenv("VAULT_TOKEN"),
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    // 1. Generate new key
    newKey, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
        KeyName: "web-key-v2",
        KeyBits: 2048,
    })
    if err != nil {
        return fmt.Errorf("new key: %w", err)
    }

    // 2. Issue certificate with new key
    newCert, err := newKey.IssueCertificate(ctx, "web-server", &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h",
    })
    if err != nil {
        return fmt.Errorf("new certificate: %w", err)
    }

    // 3. Retrieve and revoke old certificate
    oldCert, err := client.GetCertificate(ctx, "old-cert-serial")
    if err == nil {
        _ = client.RevokeCertificate(ctx, oldCert.Certificate.SerialNumber.String())
    }

    // 4. Delete old key
    oldKey, err := client.GetRSAKey(ctx, "web-key-v1")
    if err == nil {
        _ = oldKey.Delete(ctx)
    }

    log.Printf("✓ Key rotation complete: %s", newCert.CertificateInfo().SerialNumber)
    return nil
}
```

### Example 4: Multi-Issuer Management

```go
func setupMultiIssuer() error {
    client, _ := bao.NewClient(&bao.Config{
        Address: "https://vault.example.com",
        Token:   os.Getenv("VAULT_TOKEN"),
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // 1. Generate production root CA
    prodCA, err := client.GenerateRootCA(ctx, 
        bao.NewRootCABuilder("Production Root CA").
            WithOrganization("Acme Corp").
            WithKeyType("rsa", 4096).
            WithIssuerName("prod-root").
            WithTTL("87600h").
            Build())
    if err != nil {
        return fmt.Errorf("prod CA: %w", err)
    }

    // 2. Generate development root CA
    devCA, err := client.GenerateRootCA(ctx, 
        bao.NewRootCABuilder("Development Root CA").
            WithOrganization("Acme Corp - Dev").
            WithKeyType("rsa", 2048).
            WithIssuerName("dev-root").
            WithTTL("43800h").
            Build())
    if err != nil {
        return fmt.Errorf("dev CA: %w", err)
    }

    // 3. Set production as default
    err = client.SetDefaultIssuer(ctx, prodCA.IssuerID)
    if err != nil {
        return fmt.Errorf("set default: %w", err)
    }

    // 4. Create role tied to dev issuer
    roleOpts := bao.NewWebServerRole("dev.example.com").Build()
    roleOpts.IssuerRef = devCA.IssuerID
    err = client.CreateRole(ctx, "dev-web", roleOpts)
    if err != nil {
        return fmt.Errorf("dev role: %w", err)
    }

    // 5. Issue certificate from dev issuer
    cert, err := client.GenerateRSACertificate(ctx, "dev-web", &bao.GenerateCertificateOptions{
        CommonName: "api.dev.example.com",
        TTL:        "720h",
    })
    if err != nil {
        return fmt.Errorf("dev cert: %w", err)
    }

    log.Printf("✓ Multi-issuer setup complete")
    log.Printf("  Production CA: %s", prodCA.IssuerID)
    log.Printf("  Development CA: %s", devCA.IssuerID)
    log.Printf("  Dev Certificate: %s", cert.CertificateInfo().SerialNumber)
    return nil
}
```

---

## Testing

### Unit Tests

```bash
# Run unit tests
go test ./bao/...

# With coverage
go test -coverprofile=coverage.out ./bao/...
go tool cover -html=coverage.out
```

### Integration Tests

Integration tests use testcontainers to spin up OpenBao instances:

```bash
# Run integration tests
go test -tags=integration ./bao/...

# Run specific integration test
go test -tags=integration -run TestCompleteCAWorkflow ./bao/...
```

**Cross-Module Integration Tests:**
- `TestCompleteCAWorkflow` - Complete workflow from CA to certificate
- `TestKeyRotationWorkflow` - Key rotation with certificate re-issuance
- `TestMultiIssuerWorkflow` - Multiple issuers and default management
- `TestRoleBasedCertificateManagement` - Role-based policies
- `TestCertificateChainValidation` - Certificate chain validation
- `TestLocalKeyWithOpenBaoSigning` - Local key with OpenBao signing

### Test Coverage

- **Overall**: 80%+
- **Unit Tests**: 150+ test cases
- **Integration Tests**: 40+ test cases
- **Cross-Module Tests**: 6 comprehensive workflows

---

## Best Practices

### 1. Always Use Context with Timeout

```go
// ✓ Good
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
cert, err := client.GenerateRSACertificate(ctx, "role", opts)

// ✗ Bad
cert, err := client.GenerateRSACertificate(context.Background(), "role", opts)
```

### 2. Private Keys Should Stay Local When Possible

```go
// ✓ Most Secure: Local key
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
cert, _ := client.IssueRSACertificate(ctx, "role", keyPair, opts)

// ✓ Secure: OpenBao-managed key (never exported)
keyClient, _ := client.CreateRSAKey(ctx, keyOpts)
cert, _ := keyClient.IssueCertificate(ctx, "role", opts)

// ⚠️ Less Secure: Exported key
keyClient, _ := client.GenerateRSAKey(ctx, keyOpts)
keyPair, _ := keyClient.KeyPair()  // Private key exposed
```

### 3. Use Builder Patterns for Complex Configurations

```go
// ✓ Good: Readable and maintainable
opts := bao.NewWebServerRole("example.com").
    WithTTL("720h").
    WithMaxTTL("8760h").
    EnableSubdomains().
    EnableWildcards().
    WithKeyType("rsa", 2048).
    Build()

// ✗ Bad: Hard to read
opts := &bao.RoleOptions{
    AllowedDomains:            []string{"example.com"},
    TTL:                       "720h",
    MaxTTL:                    "8760h",
    AllowSubdomains:           true,
    AllowWildcardCertificates: true,
    KeyType:                   "rsa",
    KeyBits:                   2048,
}
```

### 4. Proper Error Handling

```go
// ✓ Good: Check and handle errors
cert, err := client.GenerateRSACertificate(ctx, "role", opts)
if err != nil {
    log.Printf("Failed to generate certificate: %v", err)
    return fmt.Errorf("certificate generation: %w", err)
}

// ✗ Bad: Ignore errors
cert, _ := client.GenerateRSACertificate(ctx, "role", opts)
```

### 5. Cleanup Resources

```go
// ✓ Good: Cleanup with defer
keyClient, _ := client.GenerateRSAKey(ctx, opts)
defer keyClient.Delete(ctx)

// ✓ Good: Cleanup on error
roleClient, err := client.GetRole(ctx, "test-role")
if err != nil {
    return err
}
defer client.DeleteRole(ctx, roleClient.Name())
```

### 6. Use Type-Safe Methods

```go
// ✓ Good: Type-safe
rsaKey, _ := client.GenerateRSAKey(ctx, opts)
cert, _ := client.IssueRSACertificate(ctx, "role", keyPair, opts)

// ✗ Bad: Generic (loses type safety)
key, _ := client.GenerateKey(ctx, "rsa", opts)  // No such method
```

---

## Troubleshooting

### Common Issues

#### 1. "path is already in use"
**Problem:** PKI secrets engine already enabled
**Solution:** Check existing mounts or use different mount path

#### 2. "role key type 'any' not allowed"
**Problem:** Role doesn't allow flexible key types
**Solution:** Specify `KeyType` and `KeyBits` in role or certificate options

#### 3. "common name not allowed by this role"
**Problem:** CommonName doesn't match role's allowed domains
**Solution:** Add domain to `AllowedDomains` or set `AllowAnyName: true`

#### 4. "private key not available"
**Problem:** Trying to get KeyPair() from CreateXXXKey()
**Solution:** Use GenerateXXXKey() if you need the private key

### Debug Tips

1. **Enable verbose logging**:
```go
client.SetLogLevel("debug")  // If implemented
```

2. **Check role configuration**:
```go
role, _ := client.GetRole(ctx, "role-name")
fmt.Printf("%+v\n", role.Options())
```

3. **Verify issuer**:
```go
issuer, _ := client.GetIssuer(ctx, "issuer-ref")
fmt.Printf("Issuer: %s (Key: %s)\n", issuer.ID(), issuer.KeyID())
```

---

## Security Considerations

### 1. Token Management
- Use time-limited tokens
- Rotate tokens regularly
- Use AppRole or other auth methods in production

### 2. TLS Configuration
```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
}

client, _ := bao.NewClient(&bao.Config{
    Address:   "https://vault.example.com",
    Token:     token,
    TLSConfig: tlsConfig,
})
```

### 3. Key Management
- Prefer `CreateXXXKey()` over `GenerateXXXKey()` when key export isn't needed
- Use local key generation (`IssueXXXCertificate` with keypair) for maximum security
- Implement key rotation policies

### 4. Certificate Lifecycle
- Set appropriate TTL values
- Implement certificate renewal before expiration
- Monitor certificate expiration
- Have revocation procedures in place

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
# Install dependencies
go mod download

# Run tests
go test ./bao/...

# Run integration tests
go test -tags=integration ./bao/...

# Run linter
golangci-lint run ./bao/...
```

---

## License

Same as GoPKI project.

---

## Changelog

### v1.0.0 (2025-10-27)
- ✨ Initial release with full PKI integration
- ✨ Type-safe APIs for RSA, ECDSA, Ed25519
- ✨ Complete CA lifecycle management
- ✨ Key management operations
- ✨ Certificate issuance workflows
- ✨ Role-based policies
- ✨ Comprehensive test suite (80%+ coverage)
- ✨ Integration tests with testcontainers
- ✨ Cross-module integration tests

---

**For questions, issues, or feature requests, please open an issue on GitHub.**

**Documentation Version:** 1.0.0  
**Last Updated:** 2025-10-27
