# Certificate Module

X.509 certificate creation and management with support for self-signed certificates, Certificate Authorities (CAs), and complex PKI hierarchies.

## Table of Contents
- [PKI Theory](#pki-theory)
- [Certificate Types](#certificate-types)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Tutorial](#tutorial)
- [Certificate Chains](#certificate-chains)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Features

- **Multiple Certificate Types**: Self-signed, CA certificates, and intermediate CAs
- **Type-Safe Integration**: Works with the KeyPair module's generic constraints
- **Certificate Chains**: Support for multi-level certificate hierarchies
- **Path Length Controls**: Configurable CA depth restrictions
- **PEM Format Support**: Standard PEM encoding and decoding
- **File Operations**: Save and load certificates with proper metadata
- **Certificate Verification**: Built-in certificate chain validation

## PKI Theory

### Public Key Infrastructure (PKI)

PKI is a framework that manages digital keys and certificates to enable secure communications. It consists of:

1. **Certificate Authorities (CAs)**: Trusted entities that issue certificates
2. **Registration Authorities (RAs)**: Verify identity before certificate issuance
3. **Certificates**: Digital documents that bind public keys to identities
4. **Certificate Revocation Lists (CRLs)**: Lists of revoked certificates

### X.509 Certificates

X.509 is the standard format for public key certificates, containing:

- **Subject**: Entity the certificate identifies
- **Public Key**: The actual public key
- **Issuer**: CA that issued the certificate
- **Validity Period**: Start and end dates
- **Extensions**: Additional certificate properties
- **Digital Signature**: CA's signature proving authenticity

### Trust Models

#### Hierarchical Trust Model
```
Root CA (Self-signed)
├── Intermediate CA 1
│   ├── Server Certificate (www.example.com)
│   └── Client Certificate (user@example.com)
└── Intermediate CA 2
    └── Code Signing Certificate
```

#### Web of Trust Model
Used in systems like PGP, where trust is established through multiple paths rather than a single authority.

## Certificate Types

### 1. Self-Signed Certificates

**Purpose**: Direct authentication without CA intermediary  
**Use Cases**: Development, testing, internal services  
**Trust**: Must be explicitly trusted by clients

**Characteristics**:
- Subject == Issuer (signs itself)
- No CA certificate chain required
- Not trusted by browsers by default
- Good for encrypted communication when trust is established out-of-band

### 2. CA Certificates (Root CA)

**Purpose**: Issue and sign other certificates  
**Use Cases**: Root of trust for organizations  
**Trust**: Manually installed in trust stores

**Characteristics**:
- `IsCA: true`
- `KeyUsage: CertSign + CRLSign`
- Long validity periods (10+ years)
- Configurable path length constraints

### 3. Intermediate CA Certificates

**Purpose**: Issued by root CA to sign end-entity certificates  
**Use Cases**: Operational certificate issuance, delegation  
**Trust**: Validated through certificate chain to root CA

**Characteristics**:
- `IsCA: true`
- Signed by another CA (not self-signed)
- Shorter validity than root CA
- Path length restrictions inherited from parent

### 4. End-Entity Certificates

**Purpose**: Identify servers, clients, or applications  
**Use Cases**: TLS/SSL, email encryption, code signing  
**Trust**: Validated through certificate chain

**Characteristics**:
- `IsCA: false`
- Contains subject alternative names (SANs)
- Specific key usage restrictions
- Cannot sign other certificates

## Architecture

### Core Types

```go
type Certificate struct {
    Certificate *x509.Certificate  // Parsed certificate
    PEMData     []byte            // PEM-encoded data
}

type CertificateRequest struct {
    Subject      pkix.Name    // Certificate subject
    DNSNames     []string     // Subject Alternative Names
    IPAddresses  []net.IP     // IP address SANs
    EmailAddress []string     // Email SANs
    ValidFrom    time.Time    // Validity start
    ValidFor     time.Duration // Validity period
    
    // CA-specific fields
    IsCA           bool  // Create CA certificate
    MaxPathLen     int   // Maximum CA chain depth
    MaxPathLenZero bool  // Explicitly set MaxPathLen to 0
}
```

### Key Usage Patterns

| Certificate Type | KeyUsage | ExtKeyUsage | IsCA |
|------------------|----------|-------------|------|
| Self-Signed | KeyEncipherment + DigitalSignature | ServerAuth + ClientAuth | false |
| CA Certificate | CertSign + CRLSign + DigitalSignature | None | true |
| Server Certificate | KeyEncipherment + DigitalSignature | ServerAuth | false |
| Client Certificate | DigitalSignature | ClientAuth | false |

## API Reference

### Certificate Creation

#### `CreateSelfSignedCertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error)`
Creates a self-signed certificate for direct use.

**Example:**
```go
keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
cert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "example.com"},
    DNSNames: []string{"example.com", "www.example.com"},
})
```

#### `CreateCACertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error)`
Creates a Certificate Authority certificate that can sign other certificates.

**Example:**
```go
caKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](4096)
rootCA, err := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
    Subject: pkix.Name{
        Country:      []string{"US"},
        Organization: []string{"Example Corp"},
        CommonName:   "Example Root CA",
    },
    MaxPathLen: 2, // Can create 2 levels of intermediate CAs
})
```

#### `SignCertificate[T keypair.KeyPair](caCert *Certificate, caKeyPair T, request CertificateRequest, subjectPublicKey crypto.PublicKey) (*Certificate, error)`
Signs a certificate using a CA certificate. Can create both intermediate CAs and end-entity certificates.

**End-Entity Certificate:**
```go
serverCert, err := cert.SignCertificate(
    rootCA, rootCAKeyPair,
    cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "www.example.com"},
        DNSNames: []string{"www.example.com"},
        IsCA: false, // End-entity certificate
    },
    serverKeyPair.PublicKey,
)
```

**Intermediate CA Certificate:**
```go
intermediateCA, err := cert.SignCertificate(
    rootCA, rootCAKeyPair,
    cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Example Intermediate CA"},
        IsCA: true,           // This is a CA certificate
        MaxPathLen: 0,        // Can only sign end-entity certificates
        MaxPathLenZero: true,
    },
    intermediateKeyPair.PublicKey,
)
```

### Certificate Operations

#### `(*Certificate) SaveToFile(filename string) error`
Saves a certificate to a PEM file.

#### `LoadCertificateFromFile(filename string) (*Certificate, error)`
Loads a certificate from a PEM file.

#### `ParseCertificateFromPEM(pemData []byte) (*Certificate, error)`
Parses a certificate from PEM-encoded data.

#### `VerifyCertificate(cert *Certificate, caCert *Certificate) error`
Verifies that a certificate was signed by a specific CA.

## Tutorial

### Basic Certificate Operations

#### 1. Creating a Self-Signed Certificate

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

func createSelfSignedExample() {
    // Generate key pair
    keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create certificate request
    request := cert.CertificateRequest{
        Subject: pkix.Name{
            Country:            []string{"US"},
            Province:           []string{"California"},
            Locality:           []string{"San Francisco"},
            Organization:       []string{"Example Corp"},
            OrganizationalUnit: []string{"IT Department"},
            CommonName:         "www.example.com",
        },
        DNSNames: []string{
            "www.example.com",
            "example.com",
            "*.example.com",
        },
        IPAddresses: []net.IP{
            net.ParseIP("192.168.1.1"),
        },
        EmailAddress: []string{
            "admin@example.com",
        },
    }
    
    // Create self-signed certificate
    certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Certificate created for: %s\n", certificate.Certificate.Subject.CommonName)
    fmt.Printf("Valid from: %s\n", certificate.Certificate.NotBefore)
    fmt.Printf("Valid until: %s\n", certificate.Certificate.NotAfter)
    fmt.Printf("DNS names: %v\n", certificate.Certificate.DNSNames)
    
    // Save to file
    err = certificate.SaveToFile("server.pem")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Certificate saved to server.pem")
}
```

#### 2. Creating a Simple CA

```go
func createSimpleCA() {
    // Generate CA key pair (use larger key for CA)
    caKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](4096)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create CA certificate
    caRequest := cert.CertificateRequest{
        Subject: pkix.Name{
            Country:      []string{"US"},
            Organization: []string{"Example Corp"},
            CommonName:   "Example Root CA",
        },
        // Default MaxPathLen = 0 means can only sign end-entity certificates
        // Set MaxPathLen > 0 to allow intermediate CAs
        MaxPathLen: 1, // Can create one level of intermediate CA
    }
    
    rootCA, err := cert.CreateCACertificate(caKeyPair, caRequest)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Root CA created: %s\n", rootCA.Certificate.Subject.CommonName)
    fmt.Printf("CA can sign certificates: %v\n", 
        rootCA.Certificate.KeyUsage&x509.KeyUsageCertSign != 0)
    fmt.Printf("Max path length: %d\n", rootCA.Certificate.MaxPathLen)
    
    // Save CA certificate
    err = rootCA.SaveToFile("root-ca.pem")
    if err != nil {
        log.Fatal(err)
    }
    
    // Now create a server certificate signed by this CA
    serverKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }
    
    serverRequest := cert.CertificateRequest{
        Subject: pkix.Name{
            CommonName: "www.example.com",
        },
        DNSNames: []string{"www.example.com", "example.com"},
        // IsCA: false is default - this is an end-entity certificate
    }
    
    serverCert, err := cert.SignCertificate(
        rootCA, caKeyPair, serverRequest, serverKeyPair.PublicKey)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Server certificate created: %s\n", serverCert.Certificate.Subject.CommonName)
    fmt.Printf("Issued by: %s\n", serverCert.Certificate.Issuer.CommonName)
    
    // Verify the certificate
    err = cert.VerifyCertificate(serverCert, rootCA)
    if err != nil {
        log.Fatal("Certificate verification failed:", err)
    }
    fmt.Println("✓ Certificate verification successful")
    
    // Save server certificate
    err = serverCert.SaveToFile("server-signed.pem")
    if err != nil {
        log.Fatal(err)
    }
}
```

### Advanced Certificate Chains

#### 3. Multi-Level Certificate Chain

```go
func createCertificateChain() {
    fmt.Println("=== Creating Multi-Level Certificate Chain ===")
    
    // 1. Root CA (MaxPathLen = 2)
    rootKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](4096)
    rootCA, err := cert.CreateCACertificate(rootKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{
            Country:      []string{"US"},
            Organization: []string{"Example Corp"},
            CommonName:   "Example Root CA",
        },
        MaxPathLen: 2, // Can create 2 levels of intermediate CAs
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("1. Root CA created (MaxPathLen=2): %s\n", rootCA.Certificate.Subject.CommonName)
    
    // 2. Intermediate CA Level 1 (MaxPathLen = 1) 
    intermediate1KeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](3072)
    intermediate1CA, err := cert.SignCertificate(
        rootCA, rootKeyPair,
        cert.CertificateRequest{
            Subject: pkix.Name{
                Country:      []string{"US"},
                Organization: []string{"Example Corp"},
                CommonName:   "Example Intermediate CA Level 1",
            },
            IsCA:       true,
            MaxPathLen: 1, // Can create 1 more level of intermediate CA
        },
        intermediate1KeyPair.PublicKey,
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("2. Intermediate CA L1 created (MaxPathLen=1): %s\n", 
        intermediate1CA.Certificate.Subject.CommonName)
    
    // 3. Intermediate CA Level 2 (MaxPathLen = 0)
    intermediate2KeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    intermediate2CA, err := cert.SignCertificate(
        intermediate1CA, intermediate1KeyPair,
        cert.CertificateRequest{
            Subject: pkix.Name{
                Country:      []string{"US"},
                Organization: []string{"Example Corp"},
                CommonName:   "Example Intermediate CA Level 2",
            },
            IsCA:           true,
            MaxPathLen:     0,   // Can only sign end-entity certificates
            MaxPathLenZero: true,
        },
        intermediate2KeyPair.PublicKey,
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("3. Intermediate CA L2 created (MaxPathLen=0): %s\n", 
        intermediate2CA.Certificate.Subject.CommonName)
    
    // 4. End-entity certificate (signed by Level 2 CA)
    serverKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    serverCert, err := cert.SignCertificate(
        intermediate2CA, intermediate2KeyPair,
        cert.CertificateRequest{
            Subject: pkix.Name{
                CommonName: "secure.example.com",
            },
            DNSNames: []string{"secure.example.com", "api.example.com"},
            IsCA: false, // End-entity certificate
        },
        serverKeyPair.PublicKey,
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("4. Server certificate created: %s\n", serverCert.Certificate.Subject.CommonName)
    
    // Verify the entire chain
    fmt.Println("\n=== Certificate Chain Verification ===")
    
    // Verify server cert against intermediate CA L2
    err = cert.VerifyCertificate(serverCert, intermediate2CA)
    if err != nil {
        log.Fatal("Server -> Intermediate L2 verification failed:", err)
    }
    fmt.Println("✓ Server certificate verified against Intermediate CA L2")
    
    // Verify intermediate L2 against intermediate L1
    err = cert.VerifyCertificate(intermediate2CA, intermediate1CA)
    if err != nil {
        log.Fatal("Intermediate L2 -> Intermediate L1 verification failed:", err)
    }
    fmt.Println("✓ Intermediate CA L2 verified against Intermediate CA L1")
    
    // Verify intermediate L1 against root CA
    err = cert.VerifyCertificate(intermediate1CA, rootCA)
    if err != nil {
        log.Fatal("Intermediate L1 -> Root verification failed:", err)
    }
    fmt.Println("✓ Intermediate CA L1 verified against Root CA")
    
    fmt.Println("\n✓ Complete certificate chain verification successful!")
    
    // Save all certificates
    rootCA.SaveToFile("chain-root-ca.pem")
    intermediate1CA.SaveToFile("chain-intermediate-1.pem")
    intermediate2CA.SaveToFile("chain-intermediate-2.pem")
    serverCert.SaveToFile("chain-server.pem")
    
    fmt.Println("\nCertificate chain saved:")
    fmt.Println("├── chain-root-ca.pem (Root CA)")
    fmt.Println("├── chain-intermediate-1.pem (Intermediate CA L1)")
    fmt.Println("├── chain-intermediate-2.pem (Intermediate CA L2)")
    fmt.Println("└── chain-server.pem (Server Certificate)")
}
```

### Certificate Loading and Verification

#### 4. Loading and Verifying Certificates

```go
func loadAndVerifyExample() {
    fmt.Println("=== Loading and Verifying Certificates ===")
    
    // Load certificates from files
    rootCA, err := cert.LoadCertificateFromFile("chain-root-ca.pem")
    if err != nil {
        log.Fatal("Failed to load root CA:", err)
    }
    
    serverCert, err := cert.LoadCertificateFromFile("chain-server.pem")
    if err != nil {
        log.Fatal("Failed to load server certificate:", err)
    }
    
    fmt.Printf("Loaded Root CA: %s\n", rootCA.Certificate.Subject.CommonName)
    fmt.Printf("Loaded Server Certificate: %s\n", serverCert.Certificate.Subject.CommonName)
    
    // Check certificate properties
    fmt.Printf("\nServer Certificate Details:\n")
    fmt.Printf("  Subject: %s\n", serverCert.Certificate.Subject.CommonName)
    fmt.Printf("  Issuer: %s\n", serverCert.Certificate.Issuer.CommonName)
    fmt.Printf("  DNS Names: %v\n", serverCert.Certificate.DNSNames)
    fmt.Printf("  Valid From: %s\n", serverCert.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
    fmt.Printf("  Valid Until: %s\n", serverCert.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
    fmt.Printf("  Is CA: %v\n", serverCert.Certificate.IsCA)
    fmt.Printf("  Key Usage: %d\n", serverCert.Certificate.KeyUsage)
    
    // Check if certificate is still valid
    now := time.Now()
    if now.Before(serverCert.Certificate.NotBefore) {
        fmt.Println("⚠️  Certificate is not yet valid")
    } else if now.After(serverCert.Certificate.NotAfter) {
        fmt.Println("❌ Certificate has expired")
    } else {
        fmt.Println("✓ Certificate is currently valid")
    }
    
    // Note: Direct verification will fail because we need the intermediate CAs
    // In a real application, you would verify the entire chain
    fmt.Println("\nNote: For complete verification, you would need to verify")
    fmt.Println("the entire certificate chain, not just against the root CA.")
}
```

### Different Key Algorithms

#### 5. Using Different Cryptographic Algorithms

```go
func demonstrateDifferentAlgorithms() {
    fmt.Println("=== Different Cryptographic Algorithms ===")
    
    // RSA Certificate
    fmt.Println("\n1. RSA Certificate")
    rsaKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    rsaCert, err := cert.CreateSelfSignedCertificate(rsaKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "rsa.example.com"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✓ RSA certificate created for %s\n", rsaCert.Certificate.Subject.CommonName)
    
    // ECDSA Certificate  
    fmt.Println("\n2. ECDSA Certificate")
    ecdsaKeyPair, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
    ecdsaCert, err := cert.CreateSelfSignedCertificate(ecdsaKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "ecdsa.example.com"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✓ ECDSA certificate created for %s\n", ecdsaCert.Certificate.Subject.CommonName)
    
    // Ed25519 Certificate
    fmt.Println("\n3. Ed25519 Certificate")
    ed25519KeyPair, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
    ed25519Cert, err := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "ed25519.example.com"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✓ Ed25519 certificate created for %s\n", ed25519Cert.Certificate.Subject.CommonName)
    
    // Save all certificates
    rsaCert.SaveToFile("rsa-cert.pem")
    ecdsaCert.SaveToFile("ecdsa-cert.pem")
    ed25519Cert.SaveToFile("ed25519-cert.pem")
    
    fmt.Println("\n✓ All certificates saved with different algorithms")
}
```

## Certificate Chains

### Understanding MaxPathLen

The `MaxPathLen` field controls how deep a certificate chain can be:

```go
// Root CA with MaxPathLen = 2
rootCA := cert.CertificateRequest{
    Subject:    pkix.Name{CommonName: "Root CA"},
    MaxPathLen: 2, // Can create 2 levels below
}

// This creates the hierarchy:
// Root CA (MaxPathLen=2)
// ├── Level 1 CA (MaxPathLen=1) 
// │   └── Level 2 CA (MaxPathLen=0)
// │       └── End-entity certificate
// └── Direct end-entity certificate
```

### Path Length Rules

- **MaxPathLen = -1**: No limit (unlimited depth)
- **MaxPathLen = 0**: Can only sign end-entity certificates
- **MaxPathLen = n**: Can create n levels of intermediate CAs

### Certificate Chain Validation

For a certificate chain to be valid:

1. Each certificate must be signed by the one above it
2. The root CA must be trusted
3. All certificates must be within their validity periods
4. Path length constraints must be respected
5. Key usage must be appropriate for the certificate's role

## Best Practices

### Security

1. **Key Sizes**:
   - Root CA: 4096-bit RSA or P-384 ECDSA
   - Intermediate CA: 3072-bit RSA or P-256 ECDSA  
   - End-entity: 2048-bit RSA or P-256 ECDSA

2. **Validity Periods**:
   - Root CA: 10-20 years
   - Intermediate CA: 3-5 years
   - End-entity: 1-2 years

3. **Path Length**:
   - Set appropriate MaxPathLen to prevent excessive chain depth
   - Use MaxPathLen = 0 for operational intermediate CAs

### Operational

1. **Certificate Storage**:
   - Store root CA keys offline
   - Use hardware security modules (HSMs) for CA keys
   - Regular backups with proper encryption

2. **Certificate Rotation**:
   - Plan for certificate renewal before expiration
   - Implement automated certificate deployment
   - Monitor certificate expiration dates

3. **Revocation**:
   - Implement Certificate Revocation Lists (CRLs) or OCSP
   - Have procedures for emergency revocation
   - Regular updates to revocation information

### Code Organization

1. **Error Handling**:
   ```go
   cert, err := cert.CreateSelfSignedCertificate(keyPair, request)
   if err != nil {
       return fmt.Errorf("certificate creation failed: %w", err)
   }
   ```

2. **Configuration**:
   - Use configuration files for certificate parameters
   - Validate input parameters before certificate creation
   - Implement proper logging for certificate operations

3. **Testing**:
   - Test certificate chains thoroughly
   - Verify certificate properties after creation
   - Test certificate validation logic

## Complete Example

Here's a complete working example that demonstrates all major features:

```go
package main

import (
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "log"
    "net"
    "time"
    
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    fmt.Println("=== Complete GoPKI Certificate Example ===")
    
    // 1. Self-signed certificate
    fmt.Println("\n1. Creating self-signed certificate...")
    createSelfSignedExample()
    
    // 2. Simple CA with signed certificate
    fmt.Println("\n2. Creating CA and signed certificate...")
    createSimpleCAExample()
    
    // 3. Multi-level certificate chain
    fmt.Println("\n3. Creating certificate chain...")
    createCertificateChainExample()
    
    // 4. Different algorithms
    fmt.Println("\n4. Different algorithms...")
    demonstrateDifferentAlgorithmsExample()
    
    fmt.Println("\n✅ All examples completed successfully!")
}

func createSelfSignedExample() {
    keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    
    cert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{
            Country:      []string{"US"},
            Organization: []string{"Example Corp"},
            CommonName:   "www.example.com",
        },
        DNSNames: []string{"www.example.com", "example.com"},
        IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
        ValidFor: 365 * 24 * time.Hour, // 1 year
    })
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("✓ Self-signed certificate: %s\n", cert.Certificate.Subject.CommonName)
    fmt.Printf("  Valid until: %s\n", cert.Certificate.NotAfter.Format("2006-01-02"))
    
    cert.SaveToFile("self-signed.pem")
}

func createSimpleCAExample() {
    // Create CA
    caKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](4096)
    ca, err := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{
            Country:      []string{"US"},
            Organization: []string{"Example Corp CA"},
            CommonName:   "Example Root CA",
        },
        ValidFor:   10 * 365 * 24 * time.Hour, // 10 years
        MaxPathLen: 0, // Can only sign end-entity certificates
    })
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("✓ Root CA created: %s\n", ca.Certificate.Subject.CommonName)
    
    // Create server certificate signed by CA
    serverKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    serverCert, err := cert.SignCertificate(ca, caKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "secure.example.com"},
        DNSNames: []string{"secure.example.com", "api.example.com"},
        ValidFor: 2 * 365 * 24 * time.Hour, // 2 years
    }, serverKeyPair.PublicKey)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("✓ Server certificate: %s\n", serverCert.Certificate.Subject.CommonName)
    fmt.Printf("  Issued by: %s\n", serverCert.Certificate.Issuer.CommonName)
    
    // Verify
    err = cert.VerifyCertificate(serverCert, ca)
    if err != nil {
        log.Fatal("Verification failed:", err)
    }
    fmt.Println("✓ Certificate verification successful")
    
    ca.SaveToFile("example-root-ca.pem")
    serverCert.SaveToFile("example-server.pem")
}

func createCertificateChainExample() {
    // Root CA (MaxPathLen = 1)
    rootKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](4096)
    rootCA, _ := cert.CreateCACertificate(rootKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Chain Root CA"},
        MaxPathLen: 1, // Can create 1 level of intermediate CA
    })
    
    // Intermediate CA (MaxPathLen = 0)
    intKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](3072)
    intCA, _ := cert.SignCertificate(rootCA, rootKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Chain Intermediate CA"},
        IsCA: true,
        MaxPathLen: 0,
        MaxPathLenZero: true,
    }, intKeyPair.PublicKey)
    
    // End-entity certificate
    serverKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    serverCert, _ := cert.SignCertificate(intCA, intKeyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "chain.example.com"},
        DNSNames: []string{"chain.example.com"},
    }, serverKeyPair.PublicKey)
    
    fmt.Printf("✓ Certificate chain created:\n")
    fmt.Printf("  Root CA: %s\n", rootCA.Certificate.Subject.CommonName)
    fmt.Printf("  Intermediate CA: %s\n", intCA.Certificate.Subject.CommonName)
    fmt.Printf("  Server Cert: %s\n", serverCert.Certificate.Subject.CommonName)
    
    // Verify chain
    cert.VerifyCertificate(serverCert, intCA)
    cert.VerifyCertificate(intCA, rootCA)
    fmt.Println("✓ Chain verification successful")
}

func demonstrateDifferentAlgorithmsExample() {
    algorithms := []struct {
        name string
        createKeyPair func() (interface{}, error)
    }{
        {"RSA", func() (interface{}, error) {
            return keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
        }},
        {"ECDSA", func() (interface{}, error) {
            return keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
        }},
        {"Ed25519", func() (interface{}, error) {
            return keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
        }},
    }
    
    for _, alg := range algorithms {
        keyPair, err := alg.createKeyPair()
        if err != nil {
            log.Fatal(err)
        }
        
        // Create certificate with appropriate key pair type
        var certificate *cert.Certificate
        switch kp := keyPair.(type) {
        case *algo.RSAKeyPair:
            certificate, _ = cert.CreateSelfSignedCertificate(kp, cert.CertificateRequest{
                Subject: pkix.Name{CommonName: fmt.Sprintf("%s.example.com", alg.name)},
            })
        case *algo.ECDSAKeyPair:
            certificate, _ = cert.CreateSelfSignedCertificate(kp, cert.CertificateRequest{
                Subject: pkix.Name{CommonName: fmt.Sprintf("%s.example.com", alg.name)},
            })
        case *algo.Ed25519KeyPair:
            certificate, _ = cert.CreateSelfSignedCertificate(kp, cert.CertificateRequest{
                Subject: pkix.Name{CommonName: fmt.Sprintf("%s.example.com", alg.name)},
            })
        }
        
        fmt.Printf("✓ %s certificate: %s\n", alg.name, certificate.Certificate.Subject.CommonName)
    }
}
```

---

For complete project documentation and development commands, see the main [README](../README.md).