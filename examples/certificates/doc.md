# Certificate Module Documentation

Complete documentation for the GoPKI Certificate module, demonstrating X.509 certificate creation, management, and PKI operations.

## Table of Contents
- [Overview](#overview)
- [Core Certificate Operations](#core-certificate-operations)
- [Advanced CA Hierarchies](#advanced-ca-hierarchies)
- [Multi-Algorithm Support](#multi-algorithm-support)
- [Subject Alternative Names (SAN)](#subject-alternative-names-san)
- [Format Operations](#format-operations)
- [PKCS#12 Integration](#pkcs12-integration)
- [Certificate Validation](#certificate-validation)
- [Integration & Best Practices](#integration--best-practices)

## Overview

The Certificate module provides comprehensive X.509 certificate creation and management capabilities with type-safe integration across all supported cryptographic algorithms. It supports the complete PKI lifecycle from root CA creation to end-entity certificate validation.

### Key Design Principles
- **Type Safety**: Seamless integration with keypair module's generic constraints
- **PKI Hierarchy Support**: Root CA → Intermediate CA → End-entity chains
- **Algorithm Agnostic**: Works with RSA, ECDSA, and Ed25519 keys
- **Format Flexibility**: PEM and DER formats with conversion capabilities
- **Enterprise Ready**: PKCS#12 integration, path length constraints, comprehensive SAN support

## Core Certificate Operations

### 1. Self-Signed Certificates
Self-signed certificates are certificates signed by their own private key, typically used for testing, development, or root CA certificates.

```go
import (
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

// Generate key pair
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)

// Create certificate request
request := cert.CertificateRequest{
    Subject: pkix.Name{
        Country:            []string{"US"},
        Organization:       []string{"GoPKI Examples Inc"},
        OrganizationalUnit: []string{"IT Department"},
        CommonName:         "GoPKI Self-Signed Certificate",
    },
    DNSNames:    []string{"localhost", "example.com"},
    IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
    ValidFrom:   time.Now(),
    ValidFor:    365 * 24 * time.Hour, // 1 year
}

// Create self-signed certificate
certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)

// Save certificate
err = certificate.SaveToFile("self_signed.pem")
```

**Features:**
- Generic support for all key algorithms (RSA, ECDSA, Ed25519)
- Full Subject Alternative Name (SAN) support
- Customizable validity periods
- Automatic key usage assignment (KeyEncipherment + DigitalSignature)

### 2. Certificate Authority (CA) Certificates
CA certificates can sign other certificates and are essential for PKI hierarchies.

```go
// Create CA certificate request
caRequest := cert.CertificateRequest{
    Subject: pkix.Name{
        Country:      []string{"US"},
        Organization: []string{"GoPKI Root CA"},
        CommonName:   "GoPKI Root Certificate Authority",
    },
    IsCA:       true,
    MaxPathLen: 2, // Allow up to 2 intermediate CAs
    ValidFrom:  time.Now(),
    ValidFor:   10 * 365 * 24 * time.Hour, // 10 years
}

// Create CA certificate
caCert, err := cert.CreateCACertificate(caKeyPair, caRequest)
```

**CA-Specific Features:**
- **Path Length Constraints**: Control intermediate CA depth
  - `MaxPathLen > 0`: Allow N intermediate CA levels
  - `MaxPathLen = 0`: Can only sign end-entity certificates
  - `MaxPathLen = -1`: No path length limit
- **Key Usage**: Automatic CertSign + CRLSign + DigitalSignature
- **BasicConstraints**: CA=true extension added automatically

### 3. Certificate Signing
Sign certificates using a CA certificate and private key.

```go
// Create server certificate request
serverRequest := cert.CertificateRequest{
    Subject: pkix.Name{
        Country:      []string{"US"},
        Organization: []string{"GoPKI Web Services"},
        CommonName:   "api.gopki.example.com",
    },
    DNSNames:     []string{"api.gopki.example.com", "www.gopki.example.com"},
    IPAddresses:  []net.IP{net.IPv4(192, 168, 1, 100)},
    EmailAddress: []string{"admin@gopki.example.com"},
    ValidFrom:    time.Now(),
    ValidFor:     365 * 24 * time.Hour, // 1 year
}

// Sign certificate with CA
serverCert, err := cert.SignCertificate(caCert, caKeyPair, serverRequest, &serverKeyPair.PrivateKey.PublicKey)
```

**Signing Features:**
- Supports signing both end-entity and intermediate CA certificates
- Automatic key usage determination based on `IsCA` flag
- Certificate chain validation during signing
- Full SAN support for server certificates

## Advanced CA Hierarchies

### Multi-Level Certificate Chains
Create sophisticated PKI hierarchies with proper path length constraint enforcement.

```go
// Root CA (MaxPathLen=2)
rootCA := createRootCA(MaxPathLen: 2)

// Intermediate CA (MaxPathLen=0 - can only sign end-entity certs)
intermediateRequest := cert.CertificateRequest{
    Subject: pkix.Name{
        CommonName: "GoPKI Intermediate Certificate Authority",
    },
    IsCA:       true,
    MaxPathLen: 0, // Can only sign end-entity certificates
    ValidFor:   5 * 365 * 24 * time.Hour, // 5 years
}

intermediateCert, err := cert.SignCertificate(rootCA, rootCAKey, intermediateRequest, &intermediateKeyPair.PrivateKey.PublicKey)

// End-entity certificate signed by intermediate CA
endEntityCert, err := cert.SignCertificate(intermediateCert, intermediateKeyPair, endEntityRequest, endEntityKeyPair.PublicKey)
```

### Path Length Constraint Enforcement
The module automatically enforces path length constraints:

```go
// This will FAIL - intermediate CA with MaxPathLen=0 cannot sign another CA
anotherIntermediateRequest := cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "Another Intermediate CA"},
    IsCA:    true,
}

// Results in error: "path length constraint violated"
_, err := cert.SignCertificate(intermediateCert, intermediateKeyPair, anotherIntermediateRequest, &anotherKeyPair.PrivateKey.PublicKey)
```

**Certificate Chain Structure:**
```
Root CA (MaxPathLen=2)
├── Intermediate CA (MaxPathLen=0)
│   ├── End-Entity Certificate
│   └── End-Entity Certificate
└── Another Intermediate CA (MaxPathLen=0)
    ├── End-Entity Certificate
    └── End-Entity Certificate
```

## Multi-Algorithm Support

### RSA Certificate Variants
Support for multiple RSA key sizes with security recommendations.

```go
// RSA 2048-bit (minimum recommended)
rsa2048Keys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
rsa2048Cert, _ := cert.CreateSelfSignedCertificate(rsa2048Keys, request)

// RSA 3072-bit (recommended for high security)
rsa3072Keys, _ := algo.GenerateRSAKeyPair(algo.KeySize3072)
rsa3072Cert, _ := cert.CreateSelfSignedCertificate(rsa3072Keys, request)

// RSA 4096-bit (maximum security)
rsa4096Keys, _ := algo.GenerateRSAKeyPair(algo.KeySize4096)
rsa4096Cert, _ := cert.CreateSelfSignedCertificate(rsa4096Keys, request)
```

### ECDSA Certificate Variants
Support for all NIST P-curves with different security levels.

```go
// ECDSA P-224 (224-bit, ~2048-bit RSA equivalent)
p224Keys, _ := algo.GenerateECDSAKeyPair(algo.P224)
p224Cert, _ := cert.CreateSelfSignedCertificate(p224Keys, request)

// ECDSA P-256 (256-bit, ~3072-bit RSA equivalent) - RECOMMENDED
p256Keys, _ := algo.GenerateECDSAKeyPair(algo.P256)
p256Cert, _ := cert.CreateSelfSignedCertificate(p256Keys, request)

// ECDSA P-384 (384-bit, ~7680-bit RSA equivalent)
p384Keys, _ := algo.GenerateECDSAKeyPair(algo.P384)
p384Cert, _ := cert.CreateSelfSignedCertificate(p384Keys, request)

// ECDSA P-521 (521-bit, ~15360-bit RSA equivalent)
p521Keys, _ := algo.GenerateECDSAKeyPair(algo.P521)
p521Cert, _ := cert.CreateSelfSignedCertificate(p521Keys, request)
```

### Ed25519 Certificates
Modern elliptic curve cryptography with excellent performance.

```go
// Ed25519 (fixed 256-bit, high security + performance)
ed25519Keys, _ := algo.GenerateEd25519KeyPair("")
ed25519Cert, _ := cert.CreateSelfSignedCertificate(ed25519Keys, request)
```

### Algorithm Performance Comparison
Relative performance for certificate creation:

| Algorithm | Key Generation | Certificate Creation | Total Time | Security Level |
|-----------|----------------|---------------------|------------|----------------|
| Ed25519 | Fastest | Fastest | ~0.02ms | High |
| ECDSA P-256 | Fast | Fast | ~0.05ms | High |
| ECDSA P-384 | Medium | Medium | ~0.10ms | Very High |
| RSA 2048 | Slow | Medium | ~15ms | Medium |
| RSA 3072 | Very Slow | Medium | ~35ms | High |
| RSA 4096 | Slowest | Medium | ~80ms | Very High |

## Subject Alternative Names (SAN)

### Complex SAN Combinations
Support for multiple DNS names, IP addresses, and email addresses in a single certificate.

```go
request := cert.CertificateRequest{
    Subject: pkix.Name{
        CommonName: "multi-domain.gopki.example.com",
    },
    // Multiple DNS names including wildcards
    DNSNames: []string{
        "multi-domain.gopki.example.com",
        "api.gopki.example.com",
        "www.gopki.example.com",
        "admin.gopki.example.com",
        "*.staging.gopki.example.com", // Wildcard domain
        "localhost",
    },
    // Multiple IP addresses (IPv4 and IPv6)
    IPAddresses: []net.IP{
        net.IPv4(127, 0, 0, 1),     // localhost
        net.IPv4(192, 168, 1, 100), // private network
        net.IPv4(10, 0, 0, 50),     // another private network
        net.ParseIP("::1"),         // IPv6 localhost
        net.ParseIP("2001:db8::1"), // IPv6 example
    },
    // Multiple email addresses
    EmailAddress: []string{
        "admin@gopki.example.com",
        "support@gopki.example.com",
        "security@gopki.example.com",
    },
    ValidFor: 2 * 365 * 24 * time.Hour, // 2 years
}
```

### Domain-Specific SAN Patterns

#### Web Server Certificate Pattern
```go
webServerSAN := []string{
    "example.com",
    "www.example.com",
    "api.example.com",
    "cdn.example.com",
}
```

#### API Service Certificate Pattern
```go
apiServiceSAN := []string{
    "api.service.internal",
    "api-v1.service.internal",
    "api-v2.service.internal",
    "*.microservice.internal",
}
```

#### Development Certificate Pattern
```go
developmentSAN := []string{
    "localhost",
    "dev.local",
    "*.dev.local",
    "test.local",
}
```

## Format Operations

### PEM vs DER Format Comparison
The module supports both PEM (ASCII) and DER (binary) formats with automatic conversion.

```go
// Save in both formats
certificate.SaveToFile("cert.pem")        // PEM format
certificate.SaveToDERFile("cert.der")     // DER format

// Format conversion
pemData := certificate.ToPEM()
derData := certificate.ToDER()

// Convert between formats
derData, err := cert.ConvertPEMToDER(pemData)
pemData, err := cert.ConvertDERToPEM(derData)
```

**Format Characteristics:**
- **PEM Format**: Human-readable, Base64-encoded, ~33% larger
- **DER Format**: Binary, compact, ~30% smaller, faster parsing
- **Use Cases**:
  - PEM: Configuration files, manual inspection, wide compatibility
  - DER: Performance-critical applications, binary storage, mobile apps

### Format Loading and Parsing
```go
// Load from files
pemCert, err := cert.LoadCertificateFromFile("cert.pem")
derCert, err := cert.LoadCertificateFromDERFile("cert.der")

// Parse from data
pemCert, err := cert.ParseCertificateFromPEM(pemData)
derCert, err := cert.ParseCertificateFromDER(derData)
```

### Performance Comparison
Based on 100 parsing iterations:
- **DER parsing**: ~2-3x faster than PEM
- **File size**: DER is ~30% smaller than PEM
- **Memory usage**: DER requires less memory for parsing

## PKCS#12 Integration

### Certificate Bundle Creation
PKCS#12 format allows bundling certificates and private keys in a single, password-protected file.

```go
import "github.com/jasoet/gopki/pkcs12"

// Save certificate and private key to PKCS#12
password := "secure-password-123"
err := pkcs12.SaveCertToP12(certificate, privateKey, "certificate.p12", password)
```

### Certificate Chain Bundles
Include certificate chains in PKCS#12 bundles for complete trust chain distribution.

```go
// Create certificate chain array
caCerts := []*cert.Certificate{rootCA, intermediateCA}

// Save certificate with full chain
chainPassword := "chain-password-456"
err := pkcs12.SaveCertToP12WithChain(
    certificate,
    privateKey,
    caCerts,
    "certificate_with_chain.p12",
    chainPassword
)
```

### Loading and Extraction
```go
// Load certificate from PKCS#12
loadedCert, caCerts, err := pkcs12.FromP12CertFile("certificate.p12", password)

// Load full certificate chain
certChain, err := pkcs12.LoadCertificateChainFromP12("certificate_with_chain.p12", chainPassword)

// Extract to PEM files
err = pkcs12.ExtractCertificatesFromP12("certificate.p12", password, "output/")
```

### PKCS#12 Validation and Metadata
```go
// Validate PKCS#12 file and extract metadata
metadata, err := pkcs12.ValidateP12Certificate("certificate.p12", password)

// Metadata includes:
// - Certificate count
// - Private key presence
// - CA certificate count
// - Certificate subjects and issuers
// - Validity periods
```

## Certificate Validation

### Certificate Chain Validation
Verify certificate chains using the built-in validation engine.

```go
// Verify server certificate against CA
err := cert.VerifyCertificate(serverCert, caCert)
if err != nil {
    // Validation failed - certificate is invalid
} else {
    // Certificate is valid and properly signed
}
```

**Validation Checks:**
- **Signature Verification**: Verify certificate signature using CA's public key
- **Certificate Chain**: Validate the complete certificate chain
- **Validity Period**: Check certificate is within valid time range
- **Certificate Extensions**: Verify critical extensions are properly set

### Certificate Expiration Checking
```go
now := time.Now()
cert := certificate.Certificate

if now.Before(cert.NotBefore) {
    // Certificate not yet valid
} else if now.After(cert.NotAfter) {
    // Certificate expired
} else {
    // Certificate is currently valid
    daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
    fmt.Printf("Certificate valid for %d more days\n", daysLeft)
}
```

### Certificate Information Extraction
Extract detailed certificate information for analysis and monitoring.

```go
cert := certificate.Certificate

// Basic information
serialNumber := cert.SerialNumber.String()
signatureAlgorithm := cert.SignatureAlgorithm.String()
publicKeyAlgorithm := cert.PublicKeyAlgorithm.String()
version := cert.Version
isCA := cert.IsCA

// Subject Alternative Names
dnsNames := cert.DNSNames
ipAddresses := cert.IPAddresses
emailAddresses := cert.EmailAddresses

// Fingerprint calculation (example)
fingerprint := sha256.Sum256(cert.Raw)
```

### Invalid Certificate Testing
Test certificate validation with various invalid scenarios to ensure proper security.

```go
// Create an invalid self-signed certificate
invalidCert, _ := cert.CreateSelfSignedCertificate(invalidKeyPair, invalidRequest)

// Try to validate against CA (should fail)
err := cert.VerifyCertificate(invalidCert, caCert)
if err != nil {
    // Correctly rejected invalid certificate
} else {
    // ERROR: Invalid certificate was incorrectly accepted
}
```

## Integration & Best Practices

### Certificate-KeyPair Integration
Seamless integration with the keypair module's type-safe APIs.

```go
// All algorithms work identically
algorithms := []func() (interface{}, error){
    func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) },
    func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) },
    func() (interface{}, error) { return algo.GenerateEd25519KeyPair("") },
}

for _, genFunc := range algorithms {
    keyPair, _ := genFunc()

    // Type-safe certificate creation works with any key type
    switch kp := keyPair.(type) {
    case *algo.RSAKeyPair:
        cert, _ := cert.CreateSelfSignedCertificate(kp, request)
    case *algo.ECDSAKeyPair:
        cert, _ := cert.CreateSelfSignedCertificate(kp, request)
    case *algo.Ed25519KeyPair:
        cert, _ := cert.CreateSelfSignedCertificate(kp, request)
    }
}
```

### Real-World TLS Server Setup
Complete production-ready TLS server certificate configuration.

```go
serverRequest := cert.CertificateRequest{
    Subject: pkix.Name{
        Country:            []string{"US"},
        Province:           []string{"California"},
        Locality:           []string{"San Francisco"},
        Organization:       []string{"Production Services"},
        OrganizationalUnit: []string{"Web Services"},
        CommonName:         "api.production.example.com",
    },
    DNSNames: []string{
        "api.production.example.com",
        "www.production.example.com",
        "cdn.production.example.com",
        "admin.production.example.com",
    },
    IPAddresses: []net.IP{
        net.IPv4(203, 0, 113, 10), // Public IP
        net.IPv4(203, 0, 113, 11), // Load balancer IP
    },
    EmailAddress: []string{
        "admin@production.example.com",
        "security@production.example.com",
    },
    ValidFor: 2 * 365 * 24 * time.Hour, // 2 years
}

// Sign with production CA
serverCert, err := cert.SignCertificate(productionCA, caPrivateKey, serverRequest, &serverKeyPair.PrivateKey.PublicKey)
```

### Certificate Analytics and Monitoring
Track certificate collections for operational insights.

```go
// Certificate collection analytics
type CertificateAnalytics struct {
    TotalCertificates    int
    CACertificates      int
    SelfSignedCerts     int
    EndEntityCerts      int
    AlgorithmCounts     map[string]int
    ExpiringCerts       []*cert.Certificate // Expiring within 30 days
    ExpiredCerts        []*cert.Certificate
}

// Analyze certificate directory
analytics := AnalyzeCertificateCollection("output/")
```

### Security Best Practices

#### Algorithm Selection
```go
// RECOMMENDED: Use ECDSA P-256 or Ed25519 for new certificates
preferredKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
// OR
modernKeyPair, _ := algo.GenerateEd25519KeyPair("")

// ACCEPTABLE: RSA 2048+ for compatibility requirements
compatKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize3072)
```

#### CA Hierarchy Design
```go
// Proper CA hierarchy with path length constraints
rootCA := createCA(MaxPathLen: 2)           // Can sign 2 levels of intermediate CAs
intermediateCA := createCA(MaxPathLen: 0)   // Can only sign end-entity certificates
endEntityCert := signEndEntity()            // Cannot sign other certificates
```

#### Certificate Validity Periods
```go
// Recommended validity periods
const (
    RootCAValidity        = 20 * 365 * 24 * time.Hour  // 20 years
    IntermediateCAValidity = 10 * 365 * 24 * time.Hour  // 10 years
    ServerCertValidity     = 2 * 365 * 24 * time.Hour   // 2 years
    ClientCertValidity     = 1 * 365 * 24 * time.Hour   // 1 year
)
```

#### File Security
```go
// Certificates saved with appropriate permissions
certificate.SaveToFile("cert.pem")     // 0644 (world readable)
privateKey.SaveToFile("key.pem")       // 0600 (owner only)
p12Bundle.SaveToFile("bundle.p12")     // 0600 (owner only)
```

### Performance Recommendations

#### Format Selection
- **PEM**: Use for configuration files, human inspection, wide compatibility
- **DER**: Use for performance-critical applications, binary storage, mobile apps
- **PKCS#12**: Use for secure distribution, enterprise environments

#### Certificate Storage
```go
// For high-performance applications, prefer DER format
certificate.SaveToDERFile("high_perf_cert.der")

// For configuration and compatibility, use PEM
certificate.SaveToFile("config_cert.pem")

// For secure distribution with private keys, use PKCS#12
pkcs12.SaveCertToP12(cert, privateKey, "secure_bundle.p12", password)
```

#### Caching Strategies
```go
// Cache parsed certificates to avoid repeated parsing
type CertificateCache struct {
    cache map[string]*cert.Certificate
    mutex sync.RWMutex
}

func (c *CertificateCache) GetCertificate(path string) (*cert.Certificate, error) {
    c.mutex.RLock()
    if cached, exists := c.cache[path]; exists {
        c.mutex.RUnlock()
        return cached, nil
    }
    c.mutex.RUnlock()

    // Load and cache certificate
    certificate, err := cert.LoadCertificateFromFile(path)
    if err != nil {
        return nil, err
    }

    c.mutex.Lock()
    c.cache[path] = certificate
    c.mutex.Unlock()

    return certificate, nil
}
```

### Error Handling Patterns

```go
// Comprehensive error handling for certificate operations
certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
if err != nil {
    switch {
    case errors.Is(err, cert.ErrInvalidKeyPair):
        return fmt.Errorf("invalid key pair: %w", err)
    case errors.Is(err, cert.ErrInvalidCertificateRequest):
        return fmt.Errorf("invalid certificate request: %w", err)
    case errors.Is(err, cert.ErrCertificateCreationFailed):
        return fmt.Errorf("certificate creation failed: %w", err)
    default:
        return fmt.Errorf("unexpected error: %w", err)
    }
}

// Validation error handling
err = cert.VerifyCertificate(serverCert, caCert)
if err != nil {
    switch {
    case errors.Is(err, cert.ErrCertificateExpired):
        log.Printf("Certificate expired: %v", err)
    case errors.Is(err, cert.ErrInvalidSignature):
        log.Printf("Invalid certificate signature: %v", err)
    case errors.Is(err, cert.ErrUnknownCA):
        log.Printf("Unknown certificate authority: %v", err)
    default:
        log.Printf("Certificate validation failed: %v", err)
    }
}
```

---

For complete working examples demonstrating all these features, see the `main.go` file in this directory.
For integration with other modules, see the main project [README](../../README.md).