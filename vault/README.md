# Vault PKI Integration

**Status:** 🚧 In Development (Phase 1)
**Compatibility:** OpenBao and HashiCorp Vault
**Go Version:** 1.24.5+

---

## Overview

The `vault` module provides seamless integration between GoPKI's type-safe cryptographic operations and Vault/OpenBao PKI secrets engine for centralized certificate authority management.

**Key Features:**
- 🔐 Certificate issuance and CSR signing
- 🏗️ CA management (root, intermediate)
- 🔑 Key import/export operations
- ✅ Type-safe generics (RSA, ECDSA, Ed25519)
- 🌐 Context-aware network operations
- 🔒 TLS support with security best practices
- 📦 Zero external dependencies (stdlib only)

---

## Quick Start

### Installation

```go
import "github.com/jasoet/gopki/vault"
```

### Basic Usage

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/vault"
)

func main() {
    // Create Vault client
    client, err := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   os.Getenv("VAULT_TOKEN"),
        Mount:   "pki",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Validate connection
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := client.ValidateConnection(ctx); err != nil {
        log.Fatal(err)
    }

    // Generate local keypair
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // Issue certificate from Vault (private key stays local!)
    ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    certificate, err := client.IssueCertificateWithKeyPair(ctx, "web-server", keyPair, &vault.IssueOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h", // 30 days
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Certificate issued: CN=%s, Serial=%s",
        certificate.Certificate.Subject.CommonName,
        certificate.Certificate.SerialNumber)
}
```

---

## Status: Phase 1 - Foundation

### ✅ Completed
- Module structure created
- Foundation analysis documented
- CSR support in cert module

### 🚧 In Progress (Phase 1)
- [ ] Core types and configuration
- [ ] HTTP client with context support
- [ ] Certificate operations
- [ ] Type conversions
- [ ] Unit tests

### 📅 Planned
- Phase 2: CA and key management (Week 2)
- Phase 3: Advanced features (Week 3)
- Phase 4: Documentation and CI/CD (Week 4)

---

## Documentation

- **This README:** Overview and quick start
- **[Foundation Analysis](../VAULT_FOUNDATION_ANALYSIS.md):** Technical analysis
- **[Integration Plan](../VAULT_INTEGRATION_PLAN.md):** Complete implementation plan
- **[Foundation Work](../VAULT_INTEGRATION_FOUNDATION.md):** CSR implementation details

---

## Architecture

```
Application
    ↓
vault.Client (with context.Context)
    ↓ HTTP/TLS
Vault/OpenBao PKI Engine
    ↑ certificates
GoPKI modules (cert, keypair, signing, encryption, pkcs12)
```

---

## Security

- ✅ TLS required for production
- ✅ Token management best practices
- ✅ Private keys never sent to Vault (CSR workflow)
- ✅ Context-based timeout/cancellation
- ⚠️ Ed25519 limitation: cannot be used for envelope encryption

---

## Compatibility

**Vault Versions:**
- HashiCorp Vault: 1.14+
- OpenBao: All versions

**API Compatibility:**
- Full API compatibility at consumption level
- Standard X.509, PKCS, and RFC compliance

---

## Examples

See `examples/` directory for working code:
- `examples/issue_cert/` - Certificate issuance
- `examples/sign_csr/` - CSR signing workflow
- `examples/ca_management/` - CA hierarchy

---

## Contributing

This module follows GoPKI development guidelines:
- Type-safe generics
- Context-aware operations
- Comprehensive testing (80%+ coverage)
- Security-first design

See `../CLAUDE.md` for development commands.

---

## License

Same as GoPKI project.

---

**Last Updated:** 2025-10-27
**Phase:** 1 (Foundation)
**Next Milestone:** Working certificate operations
