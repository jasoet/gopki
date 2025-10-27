# Vault PKI Integration

**Status:** ✅ Phase 1 Complete
**Compatibility:** OpenBao and HashiCorp Vault
**Go Version:** 1.24.5+
**Test Coverage:** 82.4% (90+ test cases)

---

## Overview

The `vault` module provides seamless integration between GoPKI's type-safe cryptographic operations and Vault/OpenBao PKI secrets engine for centralized certificate authority management.

**Key Features:**
- 🔐 Certificate issuance with local key generation (private keys never leave your system)
- ✍️ CSR signing workflow for maximum security
- 📋 Certificate management (retrieve, list, revoke)
- ✅ Type-safe generics (RSA, ECDSA, Ed25519)
- 🌐 Context-aware network operations with timeout/cancellation
- 🔒 TLS support with security best practices
- 📦 Zero external dependencies (stdlib only)
- 🏗️ Full HTTP mock testing (no external Vault required)

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
    "os"
    "time"

    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/vault"
)

func main() {
    // Create Vault client
    client, err := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   os.Getenv("VAULT_TOKEN"),
        Mount:   "pki", // PKI mount path (defaults to "pki")
    })
    if err != nil {
        log.Fatal(err)
    }

    // Validate connection (checks health and authentication)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := client.ValidateConnection(ctx); err != nil {
        log.Fatal(err)
    }

    // Generate local keypair (RSA, ECDSA, or Ed25519)
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

    // Save certificate and private key
    certificate.SaveToFile("certificate.pem")
    keyPair.SavePrivateKey("private_key.pem")
}
```

---

## API Reference

### Client Configuration

```go
type Config struct {
    Address   string        // Vault server address (required)
    Token     string        // Vault authentication token (required)
    Mount     string        // PKI mount path (defaults to "pki")
    Namespace string        // Vault namespace (Enterprise feature)
    TLSConfig *tls.Config   // Custom TLS configuration
    HTTPClient *http.Client // Custom HTTP client
    Timeout   time.Duration // Default request timeout
}

// Create new client
client, err := vault.NewClient(&vault.Config{
    Address: "https://vault.example.com",
    Token:   "hvs.XXXXXXXXXXXXX",
    Mount:   "pki",
    Timeout: 30 * time.Second,
})
```

### Health and Connection

```go
// Check Vault health (no authentication required)
err := client.Health(ctx)

// Validate full connection (health + authentication + mount access)
err := client.ValidateConnection(ctx)

// Ping is an alias for Health
err := client.Ping(ctx)
```

### Certificate Operations

#### Issue Certificate with Local Key Pair

The most secure method - private key never leaves your system!

```go
// Generate key pair locally (RSA, ECDSA, or Ed25519)
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
// or: keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
// or: keyPair, err := algo.GenerateEd25519KeyPair()

// Issue certificate
certificate, err := client.IssueCertificateWithKeyPair(ctx, "role-name", keyPair, &vault.IssueOptions{
    CommonName:        "app.example.com",
    AltNames:          []string{"www.app.example.com", "api.app.example.com"},
    IPSANs:            []string{"192.168.1.100"},
    URISANs:           []string{"https://app.example.com"},
    TTL:               "720h", // 30 days
    Format:            "pem",  // or "der"
    ExcludeCNFromSANs: false,  // Include CN in SANs
})
```

**Process:**
1. Key pair generated locally
2. CSR created from key pair
3. CSR sent to Vault for signing
4. Signed certificate returned
5. Private key remains on local system

#### Sign CSR

For pre-existing CSRs or advanced workflows:

```go
// Create CSR from existing key pair
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
csr, err := cert.CreateCSR(keyPair, cert.CSRRequest{
    Subject: pkix.Name{
        CommonName:   "service.example.com",
        Organization: []string{"My Company"},
    },
    DNSNames: []string{"service.example.com"},
})

// Sign with Vault
certificate, err := client.SignCSR(ctx, "role-name", csr, &vault.SignOptions{
    CommonName: "service.example.com", // Can override CSR values
    TTL:        "8760h", // 1 year
})
```

#### Get Certificate by Serial Number

```go
certificate, err := client.GetCertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
if err != nil {
    log.Fatal(err)
}

log.Printf("Certificate: %s", certificate.Certificate.Subject.CommonName)
```

#### List All Certificates

```go
serials, err := client.ListCertificates(ctx)
if err != nil {
    log.Fatal(err)
}

for _, serial := range serials {
    fmt.Printf("Serial: %s\n", serial)
}
```

#### Revoke Certificate

```go
err := client.RevokeCertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
if err != nil {
    log.Fatal(err)
}
```

---

## Complete Examples

### Example 1: Issue Certificate with RSA Key

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/vault"
)

func main() {
    client, _ := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   "hvs.XXXXXXXXXXXXX",
        Mount:   "pki",
    })

    // Validate connection
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := client.ValidateConnection(ctx); err != nil {
        log.Fatalf("Connection failed: %v", err)
    }

    // Generate RSA-2048 key pair
    keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
    if err != nil {
        log.Fatalf("Key generation failed: %v", err)
    }

    // Issue certificate
    ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    cert, err := client.IssueCertificateWithKeyPair(ctx, "web-server", keyPair, &vault.IssueOptions{
        CommonName: "app.example.com",
        AltNames:   []string{"www.app.example.com"},
        TTL:        "720h",
    })
    if err != nil {
        log.Fatalf("Certificate issuance failed: %v", err)
    }

    // Save certificate and private key
    cert.SaveToFile("certificate.pem")
    keyPair.SavePrivateKey("private_key.pem")

    log.Printf("✅ Certificate issued successfully!")
    log.Printf("   CN: %s", cert.Certificate.Subject.CommonName)
    log.Printf("   Serial: %s", cert.Certificate.SerialNumber)
    log.Printf("   Valid until: %s", cert.Certificate.NotAfter)
}
```

### Example 2: Issue Certificate with ECDSA Key

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/vault"
)

func main() {
    client, _ := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   "hvs.XXXXXXXXXXXXX",
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := client.ValidateConnection(ctx); err != nil {
        log.Fatalf("Connection failed: %v", err)
    }

    // Generate ECDSA P-256 key pair
    keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
    if err != nil {
        log.Fatalf("Key generation failed: %v", err)
    }

    // Issue certificate
    ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    cert, err := client.IssueCertificateWithKeyPair(ctx, "service-cert", keyPair, &vault.IssueOptions{
        CommonName: "service.example.com",
        AltNames:   []string{"api.service.example.com"},
        IPSANs:     []string{"10.0.1.100"},
        TTL:        "8760h", // 1 year
    })
    if err != nil {
        log.Fatalf("Certificate issuance failed: %v", err)
    }

    log.Printf("✅ ECDSA certificate issued!")
    log.Printf("   Algorithm: %s", cert.Certificate.PublicKeyAlgorithm)
}
```

### Example 3: Sign Pre-existing CSR

```go
package main

import (
    "context"
    "crypto/x509/pkix"
    "log"
    "time"

    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/vault"
)

func main() {
    client, _ := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   "hvs.XXXXXXXXXXXXX",
        Mount:   "pki",
    })

    // Create CSR locally
    keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
    csr, err := cert.CreateCSR(keyPair, cert.CSRRequest{
        Subject: pkix.Name{
            CommonName:   "microservice.example.com",
            Organization: []string{"Engineering"},
            Country:      []string{"US"},
        },
        DNSNames: []string{"microservice.example.com", "api.microservice.example.com"},
    })
    if err != nil {
        log.Fatalf("CSR creation failed: %v", err)
    }

    // Sign with Vault
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    certificate, err := client.SignCSR(ctx, "microservice-role", csr, &vault.SignOptions{
        TTL:    "720h",
        Format: "pem",
    })
    if err != nil {
        log.Fatalf("CSR signing failed: %v", err)
    }

    certificate.SaveToFile("signed_certificate.pem")
    log.Printf("✅ CSR signed successfully!")
}
```

### Example 4: List and Retrieve Certificates

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/jasoet/gopki/vault"
)

func main() {
    client, _ := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   "hvs.XXXXXXXXXXXXX",
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // List all certificates
    serials, err := client.ListCertificates(ctx)
    if err != nil {
        log.Fatalf("Failed to list certificates: %v", err)
    }

    fmt.Printf("Found %d certificates:\n", len(serials))

    // Retrieve details for each certificate
    for _, serial := range serials {
        cert, err := client.GetCertificate(ctx, serial)
        if err != nil {
            log.Printf("  ⚠️  Failed to get %s: %v", serial, err)
            continue
        }

        fmt.Printf("  📜 %s\n", serial)
        fmt.Printf("     CN: %s\n", cert.Certificate.Subject.CommonName)
        fmt.Printf("     Valid: %s to %s\n",
            cert.Certificate.NotBefore.Format("2006-01-02"),
            cert.Certificate.NotAfter.Format("2006-01-02"))
    }
}
```

### Example 5: Revoke Certificate

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jasoet/gopki/vault"
)

func main() {
    client, _ := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   "hvs.XXXXXXXXXXXXX",
        Mount:   "pki",
    })

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Revoke certificate by serial number
    serial := "39:dd:2e:90:b7:23:1f:8d"
    err := client.RevokeCertificate(ctx, serial)
    if err != nil {
        log.Fatalf("Revocation failed: %v", err)
    }

    log.Printf("✅ Certificate %s revoked", serial)
}
```

### Example 6: Error Handling

```go
package main

import (
    "context"
    "errors"
    "log"

    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/vault"
)

func main() {
    client, _ := vault.NewClient(&vault.Config{
        Address: "https://vault.example.com",
        Token:   "hvs.XXXXXXXXXXXXX",
        Mount:   "pki",
    })

    ctx := context.Background()
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    cert, err := client.IssueCertificateWithKeyPair(ctx, "web-server", keyPair, &vault.IssueOptions{
        CommonName: "app.example.com",
        TTL:        "720h",
    })
    if err != nil {
        // Check for specific error types
        if errors.Is(err, vault.ErrUnauthorized) {
            log.Fatal("Authentication failed - check your token")
        }
        if errors.Is(err, vault.ErrPermissionDenied) {
            log.Fatal("Permission denied - check your Vault policy")
        }
        if errors.Is(err, vault.ErrTimeout) {
            log.Fatal("Request timeout - check network connectivity")
        }

        // Check if it's a VaultError for detailed info
        var vaultErr *vault.VaultError
        if errors.As(err, &vaultErr) {
            log.Printf("Vault error: %s (status: %d)", vaultErr.Operation, vaultErr.StatusCode)
            for _, errMsg := range vaultErr.Errors {
                log.Printf("  - %s", errMsg)
            }
        }

        log.Fatalf("Failed: %v", err)
    }

    log.Printf("Success: %s", cert.Certificate.Subject.CommonName)
}
```

---

## Error Handling

The module provides structured error handling with predefined error types:

```go
// Predefined errors
var (
    ErrInvalidConfig         // Configuration validation failed
    ErrNotConnected          // Client not connected
    ErrUnauthorized          // Authentication failed (401)
    ErrPermissionDenied      // Authorization failed (403)
    ErrTimeout               // Request timeout
    ErrCertificateNotFound   // Certificate not found (404)
    ErrInvalidCSR            // CSR validation failed
    ErrKeyNotFound           // Key not found
    ErrRoleNotFound          // Role not found
    ErrRateLimitExceeded     // Rate limit exceeded (429)
    ErrHealthCheckFailed     // Health check failed
    ErrMountNotFound         // PKI mount not found
)

// VaultError contains detailed error information
type VaultError struct {
    Operation  string   // Operation that failed
    StatusCode int      // HTTP status code
    Errors     []string // Detailed error messages from Vault
    Err        error    // Underlying error
}

// Helper functions
vault.IsRetryable(err)     // Check if error is retryable
vault.IsAuthError(err)     // Check if error is authentication-related
vault.IsNotFoundError(err) // Check if error is not-found
```

### Error Handling Example

```go
cert, err := client.IssueCertificateWithKeyPair(ctx, "role", keyPair, opts)
if err != nil {
    // Check retryable errors
    if vault.IsRetryable(err) {
        // Implement retry logic
    }

    // Check authentication errors
    if vault.IsAuthError(err) {
        // Refresh token
    }

    // Get detailed error info
    var vaultErr *vault.VaultError
    if errors.As(err, &vaultErr) {
        log.Printf("Operation: %s", vaultErr.Operation)
        log.Printf("Status: %d", vaultErr.StatusCode)
        for _, msg := range vaultErr.Errors {
            log.Printf("  - %s", msg)
        }
    }
}
```

---

## Context Usage

All network operations support context for timeout and cancellation:

```go
// Timeout after 10 seconds
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

err := client.ValidateConnection(ctx)

// Manual cancellation
ctx, cancel := context.WithCancel(context.Background())
go func() {
    time.Sleep(5 * time.Second)
    cancel() // Cancel after 5 seconds
}()

cert, err := client.IssueCertificateWithKeyPair(ctx, role, keyPair, opts)
```

---

## Security Best Practices

### 1. Always Use TLS in Production

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    // Add client certificates if required
}

client, _ := vault.NewClient(&vault.Config{
    Address:   "https://vault.example.com",
    Token:     token,
    TLSConfig: tlsConfig,
})
```

### 2. Private Keys Stay Local

```go
// ✅ SECURE: Private key never leaves local system
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
cert, _ := client.IssueCertificateWithKeyPair(ctx, role, keyPair, opts)

// Private key is in keyPair.PrivateKey
// Only CSR was sent to Vault
```

### 3. Use Context Timeouts

```go
// ✅ GOOD: Always set timeouts
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

cert, err := client.IssueCertificateWithKeyPair(ctx, role, keyPair, opts)
```

### 4. Validate Connections

```go
// ✅ GOOD: Check connectivity before operations
if err := client.ValidateConnection(ctx); err != nil {
    log.Fatal("Cannot connect to Vault")
}
```

### 5. Handle Errors Properly

```go
// ✅ GOOD: Check and handle specific errors
cert, err := client.IssueCertificateWithKeyPair(ctx, role, keyPair, opts)
if err != nil {
    if errors.Is(err, vault.ErrUnauthorized) {
        // Refresh authentication
    }
    if vault.IsRetryable(err) {
        // Retry operation
    }
}
```

---

## Testing

The module includes 82.4% test coverage with 90+ test cases:

```bash
# Run all tests
go test -v github.com/jasoet/gopki/vault

# Run with coverage
go test -v -coverprofile=coverage.out github.com/jasoet/gopki/vault
go tool cover -html=coverage.out
```

Test coverage breakdown:
- Client operations: 29 test cases
- Certificate operations: 23 test cases
- Integration/conversion: 38 test cases
- Error handling: 15 test cases

---

## Limitations and Known Issues

### Ed25519 Envelope Encryption

⚠️ **Important:** Ed25519 certificates cannot be used for envelope encryption (PKCS#7/CMS).

```go
// This works for signing, but certificate cannot be used for envelope encryption
keyPair, _ := algo.GenerateEd25519KeyPair()
cert, _ := client.IssueCertificateWithKeyPair(ctx, role, keyPair, opts)

// ❌ This will fail with Ed25519 certificate
envelope, _ := encryption.EncryptEnvelope(data, []cert.Certificate{cert})

// ✅ Use RSA or ECDSA for envelope encryption
rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
rsaCert, _ := client.IssueCertificateWithKeyPair(ctx, role, rsaKeyPair, opts)
envelope, _ := encryption.EncryptEnvelope(data, []cert.Certificate{rsaCert})
```

---

## Phase 1 Status: ✅ Complete

### ✅ Completed Features

- [x] Core types and configuration
- [x] HTTP client with context support
- [x] Health checks and connection validation
- [x] Certificate operations:
  - [x] IssueCertificateWithKeyPair
  - [x] SignCSR
  - [x] GetCertificate
  - [x] ListCertificates
  - [x] RevokeCertificate
- [x] Type conversions (Vault ↔ GoPKI)
- [x] Comprehensive error handling
- [x] Unit tests (82.4% coverage, 90+ test cases)
- [x] HTTP mock testing (no external dependencies)
- [x] Documentation and examples

### 📅 Phase 2: CA and Key Management (Planned)

- CA operations (root, intermediate, import)
- Key import/export operations
- Role management
- Issuer configuration

### 📅 Phase 3: Advanced Features (Planned)

- Certificate rotation
- Auto-renewal support
- Batch operations
- Metrics and monitoring

### 📅 Phase 4: Production Readiness (Planned)

- CI/CD integration
- Performance benchmarks
- Integration tests with real Vault
- Production deployment guide

---

## Architecture

```
Application
    ↓
vault.Client (stdlib HTTP client)
    ↓ HTTPS/TLS
    ↓ context.Context (timeout/cancellation)
Vault/OpenBao PKI Engine
    ↑ Certificate issuance
    ↑ CSR signing
    ↓ Certificates (PEM format)
GoPKI Integration Layer
    ↓ Type conversions
    ↓ Validation
GoPKI Modules
    ├── cert (X.509 certificates, CSR)
    ├── keypair (RSA, ECDSA, Ed25519)
    ├── signing (PKCS#7)
    ├── encryption (envelope encryption)
    └── pkcs12 (PKCS#12 bundles)
```

---

## Compatibility

**Vault Versions:**
- HashiCorp Vault: 1.14+
- OpenBao: All versions

**API Compatibility:**
- Full REST API compatibility
- Standard X.509, PKCS, and RFC compliance
- No vendor-specific extensions

**Go Versions:**
- Minimum: Go 1.24.5 (generics support)
- Tested: Go 1.24.x

---

## Documentation

- **This README:** Complete API reference and examples
- **[Foundation Analysis](../VAULT_FOUNDATION_ANALYSIS.md):** Technical analysis and decision log
- **[Integration Plan](../VAULT_INTEGRATION_PLAN.md):** Complete implementation plan
- **[Foundation Work](../VAULT_INTEGRATION_FOUNDATION.md):** CSR implementation details

---

## Contributing

This module follows GoPKI development guidelines:
- Type-safe generics with keypair constraints
- Context-aware network operations
- Comprehensive testing (80%+ coverage target)
- Security-first design (TLS, token management, CSR workflow)
- Zero external dependencies (stdlib only)

See `../CLAUDE.md` for development commands and workflows.

---

## License

Same as GoPKI project.

---

**Last Updated:** 2025-10-27
**Phase:** 1 (Foundation) - ✅ Complete
**Next Milestone:** Phase 2 - CA and Key Management
**Test Coverage:** 82.4% (24 test functions, 90+ test cases)
**Lines of Code:** ~1,500 (including tests)
