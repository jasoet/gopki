# KeyPair Module

Type-safe cryptographic key pair generation and management for RSA, ECDSA, and Ed25519 algorithms.

## Table of Contents
- [Cryptographic Theory](#cryptographic-theory)
- [Type System](#type-system)
- [API Reference](#api-reference)
- [Tutorial](#tutorial)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Features

- **Type-Safe Generics**: Compile-time type checking prevents runtime errors
- **Multi-Algorithm Support**: RSA, ECDSA (P-224, P-256, P-384, P-521), and Ed25519
- **Unified Interface**: Single API for all supported algorithms
- **PEM Encoding/Decoding**: Standard PEM format support
- **File Operations**: Save and load keys with proper permissions
- **Algorithm Detection**: Automatic algorithm detection from PEM data

## Cryptographic Theory

### RSA (Rivest-Shamir-Adleman)
- **Type**: Asymmetric encryption algorithm
- **Key Sizes**: 2048, 3072, 4096 bits (2048+ recommended)
- **Security**: Based on the difficulty of factoring large integers
- **Use Cases**: Digital signatures, key exchange, general-purpose encryption
- **Performance**: Slower than elliptic curve algorithms

### ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Type**: Elliptic curve-based digital signature algorithm  
- **Curves**: P-224, P-256, P-384, P-521 (NIST curves)
- **Security**: Based on the elliptic curve discrete logarithm problem
- **Use Cases**: Digital signatures, TLS/SSL certificates
- **Performance**: Faster and smaller key sizes compared to RSA

### Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Type**: Modern elliptic curve signature algorithm
- **Key Size**: Fixed 256-bit keys
- **Security**: High security with excellent performance
- **Use Cases**: SSH keys, modern TLS, secure messaging
- **Performance**: Fastest signing and verification

## Type System

The module uses Go generics with interface constraints to ensure type safety:

```go
// Parameter types for key generation
type Param interface {
    algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// Key pair types
type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// Individual key types
type PublicKey interface {
    *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

type PrivateKey interface {
    *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}
```

### Core Functions

1. **Key Generation**: `GenerateKeyPair[T Param, K KeyPair](param T) (K, error)`
2. **PEM Operations**: Convert keys to/from PEM format
3. **File Operations**: Save and load keys with proper security
4. **Parsing**: Type-safe parsing with algorithm detection

## API Reference

### Type Definitions

#### `type PEM []byte`
Type alias for PEM-encoded data. This provides type safety and clarity when working with PEM-formatted keys and certificates.

**Usage:**
```go
// Converting []byte to PEM type
pemData := keypair.PEM(fileData)

// PEM type is returned by conversion functions
var privatePEM keypair.PEM
privatePEM, err := keypair.PrivateKeyToPEM(privateKey)
```

### Key Generation

#### `GenerateKeyPair[T Param, K KeyPair](param T) (K, error)`
Generates a cryptographic key pair using the specified algorithm and parameters.

**Type Parameters:**
- `T`: Parameter type (algo.KeySize, algo.ECDSACurve, or algo.Ed25519Config)
- `K`: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)

**Examples:**
```go
// RSA 2048-bit key pair
rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// ECDSA P-256 key pair  
ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)

// Ed25519 key pair
ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
```

### PEM Operations

#### `PrivateKeyToPEM[T PrivateKey](privateKey T) (PEM, error)`
Converts a private key to PEM format.

#### `PublicKeyToPEM[T PublicKey](publicKey T) (PEM, error)`
Converts a public key to PEM format.

#### `ParsePrivateKeyFromPEM[T PrivateKey](pemData PEM) (T, error)`
Parses a private key from PEM data with type safety.

#### `PrivateKeyFromPEM[T PrivateKey](pemData PEM) (T, string, error)`
Parses a private key and returns the detected algorithm.

### File Operations

#### `KeyPairToFiles[T KeyPair](keyPair T, privateFile, publicFile string) error`
Saves a key pair to files with proper permissions (0600 for private keys).

### Utility Functions

#### `ValidatePEMFormat(pemData PEM) error`
Validates that data is in proper PEM format.

#### `GetPublicKey[TPriv PrivateKey, TPub PublicKey](privateKey TPriv) (TPub, error)`
Extracts the public key from a private key.

## Tutorial

### Basic Usage

#### 1. Generate Different Key Types

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA key pair
    rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal("RSA generation failed:", err)
    }
    fmt.Printf("RSA key size: %d bits\n", rsaKeyPair.PrivateKey.Size()*8)
    
    // Generate ECDSA key pair
    ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
    if err != nil {
        log.Fatal("ECDSA generation failed:", err)
    }
    fmt.Printf("ECDSA curve: %s\n", ecdsaKeyPair.PrivateKey.Curve.Params().Name)
    
    // Generate Ed25519 key pair
    ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
    if err != nil {
        log.Fatal("Ed25519 generation failed:", err)
    }
    fmt.Printf("Ed25519 key length: %d bytes\n", len(ed25519KeyPair.PrivateKey))
}
```

#### 2. PEM Conversion and Parsing

```go
func demonstratePEMOperations() {
    // Generate a key pair
    keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }
    
    // Convert to PEM
    privatePEM, err := keypair.PrivateKeyToPEM(keyPair.PrivateKey)
    if err != nil {
        log.Fatal(err)
    }
    
    publicPEM, err := keypair.PublicKeyToPEM(keyPair.PublicKey)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Private key PEM:\n%s\n", privatePEM)
    fmt.Printf("Public key PEM:\n%s\n", publicPEM)
    
    // Parse back from PEM with type safety
    parsedPrivate, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](privatePEM)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify the key matches
    if parsedPrivate.N.Cmp(keyPair.PrivateKey.N) == 0 {
        fmt.Println("✓ PEM round-trip successful!")
    }
}
```

#### 3. File Operations

```go
func demonstrateFileOperations() {
    // Generate key pair
    keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }
    
    // Save to files
    err = keypair.KeyPairToFiles(keyPair, "private.pem", "public.pem")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Keys saved to private.pem and public.pem")
    
    // Load private key back
    privateData, err := os.ReadFile("private.pem")
    if err != nil {
        log.Fatal(err)
    }
    
    // Parse with type safety
    loadedKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](keypair.PEM(privateData))
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Loaded key size: %d bits\n", loadedKey.Size()*8)
}
```

#### 4. Algorithm Detection

```go
func demonstrateAlgorithmDetection() {
    // Create keys of different types
    keys := map[string]interface{}{}
    
    if rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048); err == nil {
        keys["RSA"] = rsaKeyPair.PrivateKey
    }
    
    if ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256); err == nil {
        keys["ECDSA"] = ecdsaKeyPair.PrivateKey
    }
    
    if ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair](""); err == nil {
        keys["Ed25519"] = ed25519KeyPair.PrivateKey
    }
    
    // Test algorithm detection
    for name, key := range keys {
        var pemData keypair.PEM
        var err error

        // Convert to PEM based on type
        switch k := key.(type) {
        case *rsa.PrivateKey:
            pemData, err = keypair.PrivateKeyToPEM(k)
        case *ecdsa.PrivateKey:
            pemData, err = keypair.PrivateKeyToPEM(k)
        case ed25519.PrivateKey:
            pemData, err = keypair.PrivateKeyToPEM(k)
        }
        
        if err != nil {
            continue
        }
        
        // Detect algorithm
        if _, algorithm, err := keypair.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
            fmt.Printf("%s key detected as: %s\n", name, algorithm)
        } else if _, algorithm, err := keypair.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
            fmt.Printf("%s key detected as: %s\n", name, algorithm)
        } else if _, algorithm, err := keypair.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
            fmt.Printf("%s key detected as: %s\n", name, algorithm)
        }
    }
}
```

## Best Practices

### Security

1. **Key Sizes**:
   - RSA: Use 2048 bits minimum, 3072+ for high security
   - ECDSA: P-256 for most use cases, P-384/P-521 for high security
   - Ed25519: Fixed 256-bit (equivalent to ~3072-bit RSA)

2. **File Permissions**:
   - Private keys: 0600 (owner read/write only)
   - Public keys: 0644 (world readable)

3. **Storage**:
   - Never store private keys in version control
   - Use secure key management systems for production
   - Consider hardware security modules (HSMs) for critical keys

### Performance

1. **Algorithm Choice**:
   - Ed25519: Best performance for signatures
   - ECDSA P-256: Good balance of security and performance
   - RSA: Use only when required by legacy systems

2. **Key Generation**:
   - Generate keys once and reuse
   - Use appropriate key sizes for your security requirements
   - Consider key rotation policies

### Code Organization

1. **Type Safety**:
   - Always use the generic functions for compile-time safety
   - Prefer explicit type parameters for clarity
   - Handle errors appropriately

2. **Error Handling**:
   ```go
   keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
   if err != nil {
       return fmt.Errorf("key generation failed: %w", err)
   }
   ```

3. **Resource Management**:
   ```go
   // Clear sensitive data when possible
   defer func() {
       // Zero out private key memory if needed
   }()
   ```

## Examples

### Complete Working Example

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "log"
    "os"
    
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    fmt.Println("=== GoPKI KeyPair Tutorial ===")
    
    // 1. Generate different key types
    fmt.Println("\n1. Generating different key types...")
    generateDifferentKeys()
    
    // 2. PEM operations
    fmt.Println("\n2. PEM operations...")
    demonstratePEMOperations()
    
    // 3. File operations
    fmt.Println("\n3. File operations...")
    demonstrateFileOperations()
    
    // 4. Algorithm detection
    fmt.Println("\n4. Algorithm detection...")
    demonstrateAlgorithmDetection()
    
    fmt.Println("\n✓ Tutorial completed successfully!")
}

func generateDifferentKeys() {
    // RSA
    rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✓ RSA key: %d bits\n", rsaKeyPair.PrivateKey.Size()*8)
    
    // ECDSA
    ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✓ ECDSA key: %s curve\n", ecdsaKeyPair.PrivateKey.Curve.Params().Name)
    
    // Ed25519
    ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✓ Ed25519 key: %d bytes\n", len(ed25519KeyPair.PrivateKey))
}

func demonstratePEMOperations() {
    keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    
    // Convert to PEM
    privatePEM, _ := keypair.PrivateKeyToPEM(keyPair.PrivateKey)
    publicPEM, _ := keypair.PublicKeyToPEM(keyPair.PublicKey)
    
    fmt.Printf("✓ Private PEM: %d bytes\n", len(privatePEM))
    fmt.Printf("✓ Public PEM: %d bytes\n", len(publicPEM))
    
    // Parse back
    parsedKey, _ := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](privatePEM)
    if parsedKey.N.Cmp(keyPair.PrivateKey.N) == 0 {
        fmt.Println("✓ PEM round-trip successful")
    }
}

func demonstrateFileOperations() {
    keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    
    // Save to files
    err := keypair.KeyPairToFiles(keyPair, "demo_private.pem", "demo_public.pem")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("✓ Keys saved to files")
    
    // Load and verify
    privateData, _ := os.ReadFile("demo_private.pem")
    loadedKey, _ := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](keypair.PEM(privateData))
    
    if loadedKey.Size() == keyPair.PrivateKey.Size() {
        fmt.Println("✓ File round-trip successful")
    }
    
    // Cleanup
    os.Remove("demo_private.pem")
    os.Remove("demo_public.pem")
}

func demonstrateAlgorithmDetection() {
    // Generate test keys
    rsaKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
    ecdsaKeyPair, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
    ed25519KeyPair, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
    
    keys := map[string]interface{}{
        "RSA":     rsaKeyPair.PrivateKey,
        "ECDSA":   ecdsaKeyPair.PrivateKey,
        "Ed25519": ed25519KeyPair.PrivateKey,
    }
    
    for name, key := range keys {
        var pemData keypair.PEM

        switch k := key.(type) {
        case *rsa.PrivateKey:
            pemData, _ = keypair.PrivateKeyToPEM(k)
        case *ecdsa.PrivateKey:
            pemData, _ = keypair.PrivateKeyToPEM(k)
        case ed25519.PrivateKey:
            pemData, _ = keypair.PrivateKeyToPEM(k)
        }
        
        // Try detection
        if _, algorithm, err := keypair.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
            fmt.Printf("✓ %s detected as: %s\n", name, algorithm)
        } else if _, algorithm, err := keypair.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
            fmt.Printf("✓ %s detected as: %s\n", name, algorithm)
        } else if _, algorithm, err := keypair.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
            fmt.Printf("✓ %s detected as: %s\n", name, algorithm)
        }
    }
}
```

---

For complete project documentation and development commands, see the main [README](../README.md).