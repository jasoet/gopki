# KeyPair Module Documentation

Complete documentation for the GoPKI KeyPair module, demonstrating type-safe cryptographic key pair generation and management.

## Table of Contents
- [Overview](#overview)
- [Core Features](#core-features)
- [API Approaches](#api-approaches)
- [Supported Algorithms](#supported-algorithms)
- [Format Conversion](#format-conversion)
- [Security & Best Practices](#security--best-practices)
- [Integration Examples](#integration-examples)

## Overview

The KeyPair module provides type-safe cryptographic key pair generation and management through Go generics. It supports multiple algorithms with both algorithm-specific and generic APIs, ensuring compile-time type safety and consistent interfaces.

### Key Design Principles
- **Type Safety**: Compile-time type checking through Go generics
- **Algorithm Agnostic**: Unified interfaces across RSA, ECDSA, and Ed25519
- **Format Flexibility**: Support for PEM, DER, SSH, and PKCS#12 formats
- **Security First**: Enforced minimum key sizes and secure file permissions
- **Performance Optimized**: Efficient key generation and format conversion

## Core Features

### 1. Type-Safe Key Generation
```go
// Algorithm-specific API
rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
ed25519Keys, err := algo.GenerateEd25519KeyPair()

// Generic API with type constraints
rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
```

### 2. KeyPair Manager Pattern
```go
import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
)

// Generic Manager with type safety
rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)

// Extract keys with type safety
privateKey := rsaManager.PrivateKey()
publicKey := rsaManager.PublicKey()
keyPair := rsaManager.KeyPair()
```

### 3. Comprehensive Format Support
- **PEM**: Standard ASCII armor format
- **DER**: Binary ASN.1 encoding
- **SSH**: OpenSSH public key format with optional passphrase protection
- **PKCS#12**: Password-protected key and certificate bundles

### 4. Advanced Security Features
- Enforced minimum key sizes (RSA ≥2048 bits)
- Secure file permissions (0600 for private keys)
- Constant-time key comparison
- Memory clearing for sensitive data

## API Approaches

### Algorithm-Specific APIs
Direct algorithm implementations for maximum performance and type safety:

```go
import "github.com/jasoet/gopki/keypair/algo"

// RSA with explicit key sizes
rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)  // 2048 bits
rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize3072)  // 3072 bits
rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize4096)  // 4096 bits

// ECDSA with standard curves
ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P224)    // P-224 curve
ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)    // P-256 curve
ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P384)    // P-384 curve
ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P521)    // P-521 curve

// Ed25519 (fixed 256-bit)
ed25519Keys, err := algo.GenerateEd25519KeyPair()
```

### Generic APIs with Type Constraints
Generic functions using Go's type constraint system:

```go
import "github.com/jasoet/gopki/keypair"

// Generic key generation with compile-time type safety
rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
ecdsaKeys, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
ed25519Keys, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair](algo.Ed25519Default)
```

### KeyPair Manager Pattern
Type-safe manager providing unified interface with format conversion:

```go
// Generate with full type safety
rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)

// Unified format operations
privatePEM, publicPEM, err := rsaManager.ToPEM()
privateDER, publicDER, err := rsaManager.ToDER()
privateSSH, publicSSH, err := rsaManager.ToSSH("user@host", "")

// Unified file operations with secure permissions
err = rsaManager.SaveToPEM("private.pem", "public.pem")
err = rsaManager.SaveToDER("private.der", "public.der")
err = rsaManager.SaveToSSH("id_rsa", "id_rsa.pub", "user@host", "")

// Load existing keys into Manager
loadedManager, err := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("private.pem")
```

## Supported Algorithms

### RSA (Rivest-Shamir-Adleman)
- **Key Sizes**: 2048, 3072, 4096 bits (minimum 2048 enforced)
- **Security**: Based on integer factorization difficulty
- **Use Cases**: Digital signatures, key exchange, legacy compatibility
- **Performance**: Slower than elliptic curve algorithms

```go
// Available key sizes
algo.KeySize2048  // 2048 bits (minimum)
algo.KeySize3072  // 3072 bits (recommended)
algo.KeySize4096  // 4096 bits (high security)
```

### ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Curves**: NIST P-224, P-256, P-384, P-521
- **Security**: Based on elliptic curve discrete logarithm problem
- **Use Cases**: Digital signatures, TLS certificates, modern PKI
- **Performance**: Faster than RSA with smaller key sizes

```go
// Available curves
algo.P224  // P-224 curve (224-bit, ~2048-bit RSA equivalent)
algo.P256  // P-256 curve (256-bit, ~3072-bit RSA equivalent)
algo.P384  // P-384 curve (384-bit, ~7680-bit RSA equivalent)
algo.P521  // P-521 curve (521-bit, ~15360-bit RSA equivalent)
```

### Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Size**: Fixed 256-bit keys
- **Security**: High security with excellent performance
- **Use Cases**: SSH keys, modern TLS, secure messaging
- **Performance**: Fastest signing and verification

```go
// Ed25519 uses empty string as config parameter
ed25519Keys, err := algo.GenerateEd25519KeyPair()
```

## Format Conversion

### Format Conversion Matrix
The module supports comprehensive format conversion between all supported formats:

| Source Format | Target Formats | Function |
|---------------|----------------|----------|
| KeyPair | PEM | `keypair.ToPEMFiles()` |
| KeyPair | DER | `keypair.ToDERFiles()` |
| KeyPair | SSH | `keypair.ToSSHFiles()` |
| KeyPair | PKCS#12 | `keypair.ToPKCS12File()` |
| PEM | DER | `format.PEMToDER()` |
| PEM | SSH | `format.PEMToSSH()` |
| DER | PEM | `format.DERToPEM()` |
| DER | SSH | `format.DERToSSH()` |
| SSH | PEM | `format.SSHToPEM()` |

### Format-Specific Features

#### PEM (Privacy-Enhanced Mail)
- ASCII armor format with Base64 encoding
- Standard format for certificates and keys
- Human-readable with clear boundaries

```go
// Save key pair to PEM files
err := keypair.ToPEMFiles(keyPair, "private.pem", "public.pem")

// Convert between formats
pemData, err := format.DERToPEM(derData)
```

#### DER (Distinguished Encoding Rules)
- Binary ASN.1 encoding
- Compact format for certificates and keys
- Used in many cryptographic protocols

```go
// Save key pair to DER files
err := keypair.ToDERFiles(keyPair, "private.der", "public.der")

// Convert to DER
derData, err := format.PEMToDER(pemData)
```

#### SSH (Secure Shell)
- OpenSSH public key format
- Includes algorithm identifier and comment
- Optional passphrase protection

```go
// Save to SSH format with custom comment
err := keypair.ToSSHFiles(keyPair, "private_ssh", "public.ssh", "user@example.com")

// Convert PEM to SSH format
sshData, err := format.PEMToSSH(pemData, "converted@example.com")
```

#### PKCS#12
- Password-protected format
- Can contain both keys and certificates
- Industry standard for key distribution

```go
// Save to PKCS#12 with password protection
err := keypair.ToPKCS12File(keyPair, "keystore.p12", "secure-password")
```

## Compatibility Testing & SSH Integration

### OpenSSH Compatibility (100% Compatible)
GoPKI provides full compatibility with OpenSSH tools and infrastructure:

#### SSH Key Generation and Validation
```go
// Generate SSH keys compatible with ssh-keygen
manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)

// Convert to SSH format
privateSSH, publicSSH, err := manager.ToSSH("user@example.com", "")

// SSH keys are validated with ssh-keygen during compatibility testing
// All algorithms (RSA, ECDSA, Ed25519) pass ssh-keygen validation
```

#### SSH Key Features Supported
- ✅ **All Key Types**: RSA (2048/3072/4096), ECDSA (P-256/384/521), Ed25519
- ✅ **SSH Fingerprints**: SHA256 fingerprints compatible with ssh-keygen
- ✅ **Comments**: Large comments and special characters supported
- ✅ **authorized_keys Format**: Full compatibility with OpenSSH
- ✅ **Passphrase Protection**: Optional passphrase encryption for private keys
- ✅ **Format Conversion**: PEM ↔ SSH ↔ DER conversion chains

#### SSH Advanced Testing
```go
// SSH certificate information extraction (compatibility/keypair/ssh_advanced_test.go)
func TestSSHCertificateCompatibility(t *testing.T) {
    manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
    _, publicSSH, _ := manager.ToSSH("test-user@example.com", "")

    // Extract key information using ssh-keygen
    keyInfo, err := helper.GetSSHKeyInformation([]byte(publicSSH))
    // Result: "256 SHA256:abc123... test-user@example.com (ED25519)"
}

// Multi-format conversion testing
func TestSSHFormatConversion(t *testing.T) {
    // Test conversion chain: PEM → SSH → PEM
    original, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
    sshPrivate, sshPublic, _ := original.ToSSH("chain-test", "")

    // Load back from SSH format
    reconstructed, _ := keypair.LoadFromSSHData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](sshPrivate, "")

    // Verify keys are functionally equivalent
    assert.Equal(t, original.KeyPair().PrivateKey, reconstructed.KeyPair().PrivateKey)
}
```

### Cross-Platform Interoperability
GoPKI keys work seamlessly across different systems:

#### OpenSSL Signature Interoperability
```go
// Bidirectional signature testing with OpenSSL
func TestSignatureInteroperability(t *testing.T) {
    manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
    testData := []byte("Cross-platform signature test")

    // OpenSSL sign → GoPKI verify
    signature, _ := helper.SignWithOpenSSL(testData, privatePEM, "")
    verified := ed25519.Verify(manager.PublicKey(), testData, signature)
    assert.True(t, verified, "GoPKI should verify OpenSSL Ed25519 signature")

    // GoPKI sign → OpenSSL verify
    signature := ed25519.Sign(manager.PrivateKey(), testData)
    err := helper.VerifyRawSignatureWithOpenSSL(testData, signature, publicPEM, "")
    assert.NoError(t, err, "OpenSSL should verify GoPKI Ed25519 signature")
}
```

#### SSH Key Type Detection
```go
// All key types properly detected by ssh-keygen
algorithms := []struct {
    name     string
    expected string
}{
    {"RSA-2048", "ssh-rsa"},
    {"ECDSA-P256", "ecdsa-sha2-nistp256"},
    {"Ed25519", "ssh-ed25519"},
}

for _, alg := range algorithms {
    // Generated keys have correct SSH type prefixes
    // and pass ssh-keygen validation
}
```

### Compatibility Test Coverage
- **Total SSH Tests**: 100+ test cases across all algorithms
- **OpenSSL Integration**: Bidirectional signature verification
- **Edge Case Testing**: Malformed keys, large comments, special characters
- **Format Validation**: Cross-validation with external tools

Run compatibility tests:
```bash
# Full compatibility test suite
task test:compatibility

# Specific SSH compatibility tests
go test -tags=compatibility ./compatibility/keypair/...
```

## Security & Best Practices

### Key Size Recommendations

| Algorithm | Minimum | Recommended | High Security |
|-----------|---------|-------------|---------------|
| RSA | 2048 bits | 3072 bits | 4096 bits |
| ECDSA | P-256 | P-256 | P-384/P-521 |
| Ed25519 | 256 bits (fixed) | 256 bits | 256 bits |

### File Security
- Private key files: 0600 permissions (owner read/write only)
- Public key files: 0644 permissions (world readable)
- PKCS#12 files: 0600 permissions with strong passwords

### Performance Considerations
```go
// Performance ranking (fastest to slowest)
// 1. Ed25519 - Best overall performance
// 2. ECDSA P-256 - Good balance of security and speed
// 3. ECDSA P-384/P-521 - Higher security, slower
// 4. RSA 2048 - Acceptable for compatibility
// 5. RSA 3072/4096 - Slow but very secure
```

### Key Comparison and Validation
```go
// Constant-time key comparison
same := keypair.CompareKeys(key1, key2)

// Key validation
valid := keypair.ValidateKeyPair(keyPair)

// Algorithm detection from PEM
algorithm := keypair.DetectAlgorithm(pemData)
```

## Integration Examples

### Certificate Integration
```go
// Generate key pair for certificate
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)

// Create certificate request
request := cert.CertificateRequest{
    Subject: pkix.Name{
        CommonName: "example.com",
    },
    KeyPair: keyPair,
    ValidFor: 365 * 24 * time.Hour,
}

// Create self-signed certificate
certificate, err := cert.CreateSelfSignedCertificate(request)
```

### Document Signing Integration
```go
// Generate signing key
keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)

// Create signature
signature, err := signing.SignDocument(data, keyPair, signing.SignOptions{
    Algorithm: signing.AlgorithmECDSA,
    Format:    signing.FormatPKCS7,
})

// Verify signature
valid, err := signing.VerifySignature(data, signature, keyPair.PublicKey)
```

### Encryption Integration
```go
// Generate encryption key pair
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)

// Encrypt data
encryptedData, err := encryption.EncryptData(data, keyPair.PublicKey)

// Decrypt data
decryptedData, err := encryption.DecryptData(encryptedData, keyPair.PrivateKey)
```

### Cross-Algorithm Compatibility
```go
// Test compatibility between different algorithms
algorithms := []string{"RSA", "ECDSA", "Ed25519"}
manager := keypair.NewManager()

for _, alg1 := range algorithms {
    for _, alg2 := range algorithms {
        key1, _ := manager.GenerateKeyPair(alg1, getDefaultParam(alg1))
        key2, _ := manager.GenerateKeyPair(alg2, getDefaultParam(alg2))

        compatible := keypair.TestCompatibility(key1, key2)
        fmt.Printf("%s ↔ %s: %v\n", alg1, alg2, compatible)
    }
}
```

## Error Handling

### Common Error Patterns
```go
// Key generation with proper error handling
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
if err != nil {
    if errors.Is(err, keypair.ErrInvalidKeySize) {
        return fmt.Errorf("invalid key size: %w", err)
    }
    return fmt.Errorf("key generation failed: %w", err)
}

// File operations with error handling
err = keypair.ToPEMFiles(keyPair, "private.pem", "public.pem")
if err != nil {
    if errors.Is(err, os.ErrPermission) {
        return fmt.Errorf("permission denied: %w", err)
    }
    return fmt.Errorf("file save failed: %w", err)
}
```

### Error Types
- `keypair.ErrInvalidKeySize`: Key size below minimum requirements
- `keypair.ErrUnsupportedAlgorithm`: Algorithm not supported
- `keypair.ErrInvalidFormat`: Invalid key format
- `keypair.ErrKeyMismatch`: Public/private key pair mismatch

## Performance Benchmarks

### Key Generation Performance (relative)
```
Ed25519:    1.0x (fastest)
ECDSA P-256: 1.2x
ECDSA P-384: 1.5x
RSA 2048:   15.0x
RSA 3072:   35.0x
RSA 4096:   80.0x (slowest)
```

### Format Conversion Performance
```
PEM ↔ DER:   ~1ms
PEM ↔ SSH:   ~2ms
DER ↔ SSH:   ~3ms
Any ↔ PKCS#12: ~5ms
```

---

For complete working examples, see the `main.go` file in this directory.
For integration with other modules, see the main project [README](../../README.md).