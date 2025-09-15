# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Using Taskfile (Recommended)

The project includes a comprehensive Taskfile for streamlined development. Install Task from https://taskfile.dev/installation/

```bash
# Setup and Dependencies
task setup             # Initial project setup
task                   # Show all available tasks

# Testing
task test              # Run all tests with race detection
task test:verbose      # Verbose test output
task test:coverage     # Generate coverage report
task test:keypair      # Test keypair module
task test:cert         # Test certificate module
task test:format       # Test format module
task test:specific -- TestName  # Run specific test

# Code Quality
task format            # Format all Go code
task format:check      # Check if code is formatted
task lint              # Run go vet
task lint:full         # Advanced linting with golangci-lint

# Building
task build             # Build the module
task build:examples    # Build example binaries

# Development
task dev               # Run basic examples
task dev:certs         # Run certificate examples
task examples:run      # Run all examples

# Module Management
task mod:verify        # Verify dependencies
task mod:tidy          # Clean up dependencies
task mod:update        # Update all dependencies

# Cleanup
task clean             # Clean build artifacts
task clean:cache       # Clean Go cache
task clean:all         # Clean everything

# CI/CD
task ci                # Run complete CI pipeline locally
task release:check     # Check if ready for release

# Git Operations
task git:status        # Show git status
task git:commit -- "message"  # Commit with message
```

### Manual Commands (Alternative)

```bash
# Testing
go test ./...
go test -v ./...
go test ./keypair -v
go test ./cert -v
go test -run TestGenerateRSAKeyPair ./keypair -v

# Building
go build ./...
go mod verify
go mod tidy

# Code Quality
go fmt ./...
go vet ./...

# Examples
cd examples && go run main.go
cd examples/certificates && go run main.go
```

## Architecture Overview

GoPKI is a type-safe Go library for PKI operations using generic constraints for compile-time safety.

### Core Modules

**`keypair/`** - Cryptographic key pair generation and management
- Generic interfaces with compile-time type safety using Go generics
- Support for RSA (2048+ bits), ECDSA (P-224/P-256/P-384/P-521), Ed25519
- Unified API through `GenerateKeyPair[T Param, K KeyPair](param T)` function
- Algorithm-specific implementations in `keypair/algo/`

**`cert/`** - X.509 certificate creation and management  
- Self-signed certificates and CA certificate creation
- Certificate signing with intermediate CA support
- Path length constraints for CA hierarchies
- Integrates with keypair module through generic constraints

**`keypair/format/`** - Key format conversion utilities
- PEM/DER format interchange
- SSH public key format support
- Cross-format conversion capabilities

**`examples/`** - Working demonstrations
- `main.go` - Basic key generation and certificate creation
- `certificates/` - Advanced PKI with CA hierarchies

### Generic Type System

The library uses Go generics for type safety:

```go
// Parameter constraints for key generation
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair type constraints
type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}
```

Usage patterns:
```go
// RSA key generation with type safety
rsaKeys, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// ECDSA key generation
ecdsaKeys, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
```

### Algorithm Implementation Structure

Each algorithm has its own package in `keypair/algo/`:
- `rsa.go` - RSA key operations with KeySize parameter
- `ecdsa.go` - ECDSA operations with ECDSACurve parameter  
- `ed25519.go` - Ed25519 operations with Ed25519Config parameter

### Certificate Operations

Certificate creation follows a request-based pattern:
```go
certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "example.com"},
    DNSNames: []string{"example.com", "www.example.com"},
    ValidFor: 365 * 24 * time.Hour,
})
```

CA certificates support path length constraints for controlling certificate chain depth.

## Key Development Patterns

### Type-Safe Key Generation
Always use the generic `GenerateKeyPair` function with proper type constraints. The compiler will catch type mismatches at build time.

### Error Handling
All functions return explicit errors. Key generation enforces minimum security standards (e.g., RSA keys must be ≥2048 bits).

### File Operations
The library includes utilities for saving keys and certificates with proper file permissions. Use the provided functions rather than manual file I/O.

### Testing Strategy
- Unit tests for each algorithm implementation
- Cross-compatibility tests between algorithms
- File I/O and error handling test coverage
- Integration tests with real certificate operations

### Format Conversions
Use the `keypair/format/` package for converting between PEM, DER, and SSH formats. This handles the complexity of format-specific encoding requirements.

## Module Dependencies

- `golang.org/x/crypto` - Extended cryptographic primitives
- Standard library packages: `crypto/*`, `encoding/pem`, `crypto/x509`

The module has minimal external dependencies and focuses on standard library compatibility.