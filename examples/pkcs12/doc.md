# PKCS#12 Module Documentation

## Overview

The PKCS#12 module provides comprehensive utilities for creating and parsing PKCS#12 files (also known as P12 or PFX files). PKCS#12 is a binary format defined in RFC 7292 for storing cryptographic objects including private keys, certificates, and certificate chains in a single password-protected file.

This module integrates seamlessly with the GoPKI ecosystem, providing type-safe operations for certificate and key bundling while maintaining compatibility with standard PKCS#12 implementations across different platforms and applications.

## Table of Contents

- [Key Features](#key-features)
- [Use Cases](#use-cases)
- [API Reference](#api-reference)
- [Quick Start](#quick-start)
- [Advanced Usage](#advanced-usage)
- [Security Considerations](#security-considerations)
- [Integration Guide](#integration-guide)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Key Features

### ✅ **Comprehensive Format Support**
- Create P12 files from private keys and certificates
- Parse existing P12 files to extract cryptographic materials
- Support for certificate chains and multiple certificates
- Compatible with all major platforms (Windows, macOS, Linux)

### ✅ **Multi-Algorithm Support**
- **RSA**: 2048+ bit keys (recommended for web servers)
- **ECDSA**: All standard curves (P-224, P-256, P-384, P-521)
- **Ed25519**: Modern high-performance algorithm

### ✅ **Type-Safe Integration**
- Seamless integration with `keypair.Manager`
- Works with all GoPKI certificate types
- Generic function signatures prevent runtime type errors
- Compile-time safety for all operations

### ✅ **Security Features**
- Password protection with configurable encryption
- Configurable iteration counts for key strengthening
- Friendly names for certificate identification
- Validation and verification of P12 contents

### ✅ **Developer Experience**
- Quick utility functions for common operations
- Comprehensive error handling and validation
- Test P12 generation for development
- Extensive documentation and examples

## Use Cases

### 🌐 **Web Server Deployment**
Bundle web server certificates with their private keys for easy deployment across different web servers (Apache, Nginx, IIS).

```go
// Create web server certificate bundle
err := pkcs12.CreateP12File("webserver.p12", privateKey, serverCert,
    []*x509.Certificate{intermediateCert}, pkcs12.CreateOptions{
        Password: "secure_password",
        FriendlyName: "Web Server Certificate",
        Iterations: 4096,
    })
```

### 🔐 **Client Authentication**
Create client certificates for mutual TLS authentication in enterprise applications.

```go
// Create client authentication certificate
err := pkcs12.QuickCreateP12("client.p12", "password", clientKey, clientCert)
```

### 📱 **Cross-Platform Migration**
Export certificates from one system and import them into another, maintaining compatibility across different operating systems and applications.

### 🔒 **Code Signing**
Bundle code signing certificates for software distribution and application signing.

### 🏢 **Enterprise PKI**
Distribute employee certificates and corporate CA certificates in a standardized format.

## API Reference

### Core Functions

#### `CreateP12File[T keypair.PrivateKey](filename, privateKey, certificate, caCerts, opts) error`

Creates a PKCS#12 file with full control over options.

**Parameters:**
- `filename`: Output file path
- `privateKey`: Private key (RSA, ECDSA, or Ed25519)
- `certificate`: Primary certificate
- `caCerts`: Optional CA certificate chain
- `opts`: Creation options (password, friendly name, iterations)

**Returns:** Error if creation fails

#### `LoadFromP12File(filename, opts) (*P12Container, error)`

Loads and parses a PKCS#12 file.

**Parameters:**
- `filename`: P12 file path
- `opts`: Load options (password, trusted certificates)

**Returns:** P12Container with parsed contents or error

#### `QuickCreateP12[T keypair.PrivateKey](filename, password, privateKey, certificate) error`

Convenience function for simple P12 creation with default options.

#### `QuickLoadP12(filename, password) (*P12Container, error)`

Convenience function for simple P12 loading with minimal configuration.

### Container Operations

#### `P12Container.Validate() error`

Validates the integrity of the P12 container and its contents.

#### `P12Container.ExtractCertificateChain() []*x509.Certificate`

Extracts the complete certificate chain from the container.

#### `P12Container.GetKeyType() string`

Returns the type of private key contained in the P12 file.

### Configuration Types

#### `CreateOptions`

```go
type CreateOptions struct {
    Password     string // Password for P12 protection
    FriendlyName string // Human-readable certificate name
    Iterations   int    // Key derivation iterations (default: 2048)
}
```

#### `LoadOptions`

```go
type LoadOptions struct {
    Password     string              // Password for P12 decryption
    TrustedCerts []*x509.Certificate // Additional trusted certificates
}
```

## Quick Start

### 1. Basic P12 Creation

```go
package main

import (
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/pkcs12"
)

func main() {
    // Generate key pair
    manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)

    // Create certificate
    certificate, _ := cert.CreateSelfSignedCertificate(manager.KeyPair(), cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "example.com"},
        ValidFor: 365 * 24 * time.Hour,
    })

    // Create P12 file
    err := pkcs12.QuickCreateP12("certificate.p12", "password123",
        manager.PrivateKey(), certificate.Certificate)
    if err != nil {
        log.Fatal(err)
    }
}
```

### 2. Loading P12 Files

```go
// Load P12 file
container, err := pkcs12.QuickLoadP12("certificate.p12", "password123")
if err != nil {
    log.Fatal(err)
}

// Access contents
fmt.Printf("Certificate: %s\n", container.Certificate.Subject.CommonName)
fmt.Printf("Key Type: %s\n", container.GetKeyType())

// Validate container
if err := container.Validate(); err != nil {
    log.Printf("Validation warning: %v", err)
}
```

## Advanced Usage

### Certificate Chains

```go
// Create P12 with certificate chain
opts := pkcs12.CreateOptions{
    Password:     "secure_password",
    FriendlyName: "Server with Chain",
    Iterations:   4096,
}

// Include intermediate and root CA certificates
caCerts := []*x509.Certificate{intermediateCert, rootCert}
err := pkcs12.CreateP12File("server_chain.p12", serverKey, serverCert, caCerts, opts)
```

### Custom Security Options

```go
// High-security P12 for sensitive applications
highSecurityOpts := pkcs12.CreateOptions{
    Password:     "very_long_and_complex_password_2024",
    FriendlyName: "High Security Certificate",
    Iterations:   16384, // Very high iteration count
}

err := pkcs12.CreateP12File("high_security.p12", privateKey, certificate, nil, highSecurityOpts)
```

### Integration with KeyPair Manager

```go
// Load existing key from PEM and create P12
manager, err := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("existing.pem")
if err != nil {
    log.Fatal(err)
}

// Validate loaded key
if err := manager.Validate(); err != nil {
    log.Fatal("Invalid key pair:", err)
}

// Create P12 from loaded key
err = pkcs12.QuickCreateP12("from_pem.p12", "password",
    manager.PrivateKey(), existingCertificate)
```

## Security Considerations

### 🔐 **Password Security**

**Weak Passwords (Avoid):**
- `password123` - Dictionary word with numbers
- `123456` - Sequential numbers
- `qwerty` - Keyboard patterns

**Strong Passwords (Recommended):**
- `Tr0ub4dor&3` - Mixed case, numbers, symbols
- `correct-horse-battery-staple-2024` - Long passphrase with year
- Use password managers for generated passwords

### 🔒 **Iteration Counts**

| Security Level | Iterations | Use Case |
|---------------|------------|----------|
| **Basic** | 2048 | Development, testing |
| **Standard** | 4096 | Production web services |
| **High** | 8192 | Financial, healthcare |
| **Maximum** | 16384+ | Government, military |

### 🛡️ **File Security**

```go
// Create P12 with secure file permissions
err := pkcs12.CreateP12File("secure.p12", privateKey, cert, nil, opts)
if err == nil {
    // Set restrictive permissions (owner read/write only)
    os.Chmod("secure.p12", 0600)
}
```

### ⚠️ **Common Security Mistakes**

1. **Weak Passwords**: Using easily guessable passwords
2. **Low Iterations**: Using default iteration counts for sensitive data
3. **Insecure Storage**: Storing P12 files with world-readable permissions
4. **Password Reuse**: Using the same password for multiple P12 files
5. **No Validation**: Skipping container validation after creation/loading

## Integration Guide

### With KeyPair Manager

```go
// Generate key with Manager
manager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)

// Get key information
info, _ := manager.GetInfo()
fmt.Printf("Algorithm: %s, Curve: %s\n", info.Algorithm, info.Curve)

// Create P12
err := pkcs12.QuickCreateP12("ecdsa.p12", "password", manager.PrivateKey(), certificate)
```

### With Certificate Module

```go
// Create CA hierarchy
caCert, _ := cert.CreateCACertificate(caKeys, caRequest)
intermediateCert, _ := cert.SignCertificate(caCert, caKeys, intermediateRequest, intermediatePublicKey)
serverCert, _ := cert.SignCertificate(intermediateCert, intermediateKeys, serverRequest, serverPublicKey)

// Bundle with complete chain
chain := []*x509.Certificate{intermediateCert.Certificate, caCert.Certificate}
err := pkcs12.CreateP12File("server_with_chain.p12", serverKey, serverCert.Certificate, chain, opts)
```

### Cross-Format Workflows

```go
// PEM → P12 → DER workflow
// 1. Load from PEM
manager, _ := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("input.pem")

// 2. Create P12
pkcs12.QuickCreateP12("output.p12", "password", manager.PrivateKey(), certificate)

// 3. Save as DER
manager.SaveToDER("output.der", "output_public.der")
```

## Best Practices

### 📋 **Development Workflow**

1. **Use KeyPair Manager** for consistent key management
2. **Validate all inputs** before creating P12 files
3. **Test with different passwords** and iteration counts
4. **Use QuickCreateP12** for simple use cases
5. **Use CreateP12File** when you need full control

### 🔧 **Production Deployment**

1. **Use strong passwords** (see Security Considerations)
2. **Set appropriate iteration counts** based on security requirements
3. **Include certificate chains** for proper validation
4. **Set restrictive file permissions** (0600)
5. **Validate P12 containers** after creation and before deployment

### 🧪 **Testing**

```go
// Generate test P12 for development
err := pkcs12.GenerateTestP12("test.p12", "test_password")
if err != nil {
    t.Fatalf("Failed to generate test P12: %v", err)
}

// Load and validate
container, err := pkcs12.QuickLoadP12("test.p12", "test_password")
assert.NoError(t, err)
assert.NoError(t, container.Validate())
```

### 📦 **Distribution**

1. **Document password requirements** for end users
2. **Provide installation instructions** for different platforms
3. **Include certificate chain** for proper trust establishment
4. **Test on target platforms** before distribution

## Troubleshooting

### Common Errors and Solutions

#### ❌ **"Invalid password"**
- **Cause**: Wrong password provided
- **Solution**: Verify password is correct, check for typos

#### ❌ **"Failed to parse P12"**
- **Cause**: Corrupted file or incompatible format
- **Solution**: Re-create P12 file, check file integrity

#### ❌ **"Certificate validation failed"**
- **Cause**: Missing certificate chain or expired certificates
- **Solution**: Include full certificate chain, check certificate validity

#### ❌ **"Unsupported key type"**
- **Cause**: Trying to use unsupported private key type
- **Solution**: Use RSA, ECDSA, or Ed25519 keys only

### Performance Considerations

#### **Iteration Count vs. Performance**

| Iterations | Creation Time | Security Level |
|-----------|---------------|----------------|
| 2048 | ~10ms | Basic |
| 4096 | ~20ms | Standard |
| 8192 | ~40ms | High |
| 16384 | ~80ms | Maximum |

#### **Optimization Tips**

1. **Use appropriate iteration counts** - higher isn't always necessary
2. **Cache P12 containers** when loading multiple times
3. **Use QuickCreateP12** for simple use cases to reduce overhead
4. **Validate only when necessary** - skip validation for trusted sources

### Platform-Specific Notes

#### **Windows**
- P12 files can be imported into Windows Certificate Store
- Use `.pfx` extension for better Windows compatibility
- Test with IIS and other Windows applications

#### **macOS**
- P12 files can be imported into Keychain Access
- Requires admin privileges for system keychain import
- Test with Safari and other macOS applications

#### **Linux**
- Compatible with OpenSSL and most Linux applications
- Can be converted to PEM format using OpenSSL tools
- Test with Apache, Nginx, and other server software

## Example Use Cases

### 🌐 **Web Server Certificate**

```go
// Create production web server certificate
webOpts := pkcs12.CreateOptions{
    Password:     os.Getenv("WEB_CERT_PASSWORD"),
    FriendlyName: "Production Web Server - example.com",
    Iterations:   4096,
}

err := pkcs12.CreateP12File("webserver.p12", serverKey, serverCert,
    []*x509.Certificate{intermediateCert}, webOpts)
```

### 🔐 **Client Authentication**

```go
// Create client authentication certificate for enterprise use
clientOpts := pkcs12.CreateOptions{
    Password:     generateSecurePassword(),
    FriendlyName: fmt.Sprintf("Employee Certificate - %s", employeeName),
    Iterations:   8192, // Higher security for client certs
}

err := pkcs12.CreateP12File(fmt.Sprintf("client_%s.p12", employeeID),
    clientKey, clientCert, []*x509.Certificate{corporateCA}, clientOpts)
```

### 📱 **Code Signing**

```go
// Create code signing certificate for software distribution
codeSignOpts := pkcs12.CreateOptions{
    Password:     os.Getenv("CODE_SIGN_PASSWORD"),
    FriendlyName: "Software Publisher Certificate",
    Iterations:   10000, // Maximum security for code signing
}

err := pkcs12.CreateP12File("codesign.p12", codeSignKey, codeSignCert, nil, codeSignOpts)
```

---

## Additional Resources

- **RFC 7292**: PKCS #12: Personal Information Exchange Syntax v1.1
- **GoPKI Documentation**: See other module documentation for integration examples
- **OpenSSL Compatibility**: P12 files created by this module are compatible with OpenSSL
- **Testing**: Run `go run main.go` in this directory for comprehensive examples

For more examples and use cases, see the `main.go` file in this directory which demonstrates all aspects of PKCS#12 operations in practical scenarios.