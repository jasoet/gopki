# JWK - JSON Web Key

[![Go Reference](https://pkg.go.dev/badge/github.com/jasoet/gopki/jose/jwk.svg)](https://pkg.go.dev/github.com/jasoet/gopki/jose/jwk)
[![Coverage](https://img.shields.io/badge/coverage-79.6%25-brightgreen)](./coverage.out)

Implementation of JSON Web Key (JWK) as defined in [RFC 7517](https://tools.ietf.org/html/rfc7517).

## Overview

The `jwk` package provides bidirectional conversion between GoPKI key pairs and JWK format, enabling:

- **Export**: Convert GoPKI/stdlib keys to JWK format
- **Import**: Convert JWK format to GoPKI/stdlib keys
- **JWK Sets**: Manage collections of keys (JWKS)
- **Validation**: Ensure JWK structure integrity

## Supported Key Types

| Key Type | JWK kty | Curves/Sizes | RFC |
|----------|---------|--------------|-----|
| RSA      | `RSA`   | 2048, 3072, 4096 bits | RFC 7518 §6.3 |
| ECDSA    | `EC`    | P-256, P-384, P-521 | RFC 7518 §6.2 |
| Ed25519  | `OKP`   | Ed25519 | RFC 8037 |

## Quick Start

### Export GoPKI Key to JWK

```go
package main

import (
    "fmt"
    "github.com/jasoet/gopki/jose/jwk"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate key pair
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // Convert to JWK
    jwkKey, err := jwk.FromPublicKey(keyPair.PublicKey, "sig", "my-key-1")
    if err != nil {
        panic(err)
    }

    // Serialize to JSON
    jsonData, _ := jwkKey.MarshalIndent("", "  ")
    fmt.Println(string(jsonData))
}
```

### Import JWK to GoPKI Key

```go
package main

import (
    "crypto/rsa"
    "github.com/jasoet/gopki/jose/jwk"
)

func main() {
    jwkJSON := []byte(`{
        "kty": "RSA",
        "use": "sig",
        "kid": "my-key-1",
        "n": "0vx7agoebGcQ...",
        "e": "AQAB"
    }`)

    // Parse JWK
    jwkKey, err := jwk.Parse(jwkJSON)
    if err != nil {
        panic(err)
    }

    // Convert to public key
    publicKey, err := jwkKey.ToPublicKey()
    if err != nil {
        panic(err)
    }

    // Type assertion to specific key type
    rsaKey := publicKey.(*rsa.PublicKey)
    // Use rsaKey...
}
```

### Working with JWK Sets

```go
package main

import (
    "github.com/jasoet/gopki/jose/jwk"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Create keys
    rsa1, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
    rsa2, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
    ec1, _ := algo.GenerateECDSAKeyPair(algo.P256)

    // Convert to JWKs
    jwk1, _ := jwk.FromPublicKey(rsa1.PublicKey, "sig", "rsa-2024-01")
    jwk2, _ := jwk.FromPublicKey(rsa2.PublicKey, "enc", "rsa-2024-02")
    jwk3, _ := jwk.FromPublicKey(ec1.PublicKey, "sig", "ec-2024-01")

    // Create JWK Set
    jwkSet := &jwk.JWKSet{}
    jwkSet.Add(jwk1)
    jwkSet.Add(jwk2)
    jwkSet.Add(jwk3)

    // Find by key ID
    key, err := jwkSet.FindByKeyID("rsa-2024-01")
    if err != nil {
        panic(err)
    }

    // Find by use
    sigKeys := jwkSet.FindByUse("sig")
    println("Signature keys:", len(sigKeys)) // Output: 2

    // Serialize to JSON
    jsonData, _ := jwkSet.MarshalIndent("", "  ")
    println(string(jsonData))
}
```

## API Reference

### JWK Type

```go
type JWK struct {
    // Common parameters
    KeyType   string   `json:"kty"`           // "RSA", "EC", "OKP", "oct"
    Use       string   `json:"use,omitempty"` // "sig" or "enc"
    KeyID     string   `json:"kid,omitempty"` // Key identifier

    // RSA parameters
    N string `json:"n,omitempty"` // Modulus (Base64URL)
    E string `json:"e,omitempty"` // Exponent (Base64URL)

    // EC parameters
    Curve string `json:"crv,omitempty"` // "P-256", "P-384", "P-521"
    X     string `json:"x,omitempty"`   // X coordinate (Base64URL)
    Y     string `json:"y,omitempty"`   // Y coordinate (Base64URL)

    // OKP parameters (Ed25519)
    // Uses Curve ("Ed25519") and X (public key bytes)
}
```

### Export Functions

#### FromPublicKey

```go
func FromPublicKey(key keypair.GenericPublicKey, use, kid string) (*JWK, error)
```

Convert a Go standard library public key to JWK.

**Parameters:**
- `key`: Public key (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
- `use`: Key use ("sig" for signature, "enc" for encryption, or empty)
- `kid`: Key ID (optional identifier)

**Returns:**
- `*JWK`: The JWK representation
- `error`: Conversion error

**Example:**

```go
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
jwkKey, err := jwk.FromPublicKey(keyPair.PublicKey, "sig", "my-key-1")
```

#### FromGoPKIKeyPair

```go
func FromGoPKIKeyPair[K keypair.KeyPair](keyPair K, use, kid string) (*JWK, error)
```

Convert a GoPKI key pair to JWK (public key only).

**Type Parameters:**
- `K`: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, *algo.Ed25519KeyPair)

**Example:**

```go
rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
jwkKey, err := jwk.FromGoPKIKeyPair(rsaKeys, "sig", "my-key-1")
```

### Import Functions

#### ToPublicKey

```go
func (j *JWK) ToPublicKey() (keypair.GenericPublicKey, error)
```

Convert a JWK to a Go standard library public key.

**Returns:**
- `keypair.GenericPublicKey`: The public key (type assertion required)
- `error`: Conversion error

**Example:**

```go
jwkKey, _ := jwk.Parse(jwkJSON)
publicKey, err := jwkKey.ToPublicKey()
rsaKey := publicKey.(*rsa.PublicKey) // Type assertion
```

### Parsing and Serialization

#### Parse

```go
func Parse(data []byte) (*JWK, error)
```

Parse a JWK from JSON bytes.

**Example:**

```go
jwkJSON := []byte(`{"kty":"RSA","n":"...","e":"AQAB"}`)
jwkKey, err := jwk.Parse(jwkJSON)
```

#### Marshal

```go
func (j *JWK) Marshal() ([]byte, error)
```

Serialize the JWK to JSON bytes.

#### MarshalIndent

```go
func (j *JWK) MarshalIndent(prefix, indent string) ([]byte, error)
```

Serialize the JWK to indented JSON bytes for pretty printing.

#### IsPrivate

```go
func (j *JWK) IsPrivate() bool
```

Returns true if this JWK contains private key material.

### JWK Set Operations

#### JWKSet Type

```go
type JWKSet struct {
    Keys []JWK `json:"keys"`
}
```

#### ParseSet

```go
func ParseSet(data []byte) (*JWKSet, error)
```

Parse a JWK Set from JSON bytes.

**Example:**

```go
jwksJSON := []byte(`{"keys":[{"kty":"RSA","n":"...","e":"AQAB"}]}`)
jwkSet, err := jwk.ParseSet(jwksJSON)
```

#### FindByKeyID

```go
func (s *JWKSet) FindByKeyID(kid string) (*JWK, error)
```

Find a JWK by its Key ID.

**Example:**

```go
key, err := jwkSet.FindByKeyID("my-key-1")
```

#### FindByUse

```go
func (s *JWKSet) FindByUse(use string) []JWK
```

Find all JWKs with the specified use ("sig" or "enc").

**Example:**

```go
sigKeys := jwkSet.FindByUse("sig")
```

#### Add

```go
func (s *JWKSet) Add(key *JWK)
```

Add a JWK to the set.

#### Remove

```go
func (s *JWKSet) Remove(kid string) bool
```

Remove a JWK from the set by its Key ID. Returns true if removed.

#### Len

```go
func (s *JWKSet) Len() int
```

Returns the number of keys in the set.

## Use Cases

### 1. OIDC Discovery

Publish public keys for JWT verification:

```go
// Create JWK Set with signing keys
jwkSet := &jwk.JWKSet{}

// Add current signing key
currentKey, _ := jwk.FromPublicKey(currentRSAKey, "sig", "2024-01")
jwkSet.Add(currentKey)

// Add previous key for rotation
previousKey, _ := jwk.FromPublicKey(previousRSAKey, "sig", "2023-12")
jwkSet.Add(previousKey)

// Serve at /.well-known/jwks.json
jsonData, _ := jwkSet.Marshal()
http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write(jsonData)
})
```

### 2. Key Rotation

Manage multiple keys during rotation:

```go
// Load existing JWKS
jwkSet, _ := jwk.ParseSet(existingJWKS)

// Generate new key
newKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
newJWK, _ := jwk.FromPublicKey(newKeyPair.PublicKey, "sig", "2024-02")

// Add new key
jwkSet.Add(newJWK)

// Remove old key after grace period
jwkSet.Remove("2023-01")

// Publish updated JWKS
updatedJSON, _ := jwkSet.Marshal()
```

### 3. Multi-Algorithm Support

Support multiple signature algorithms:

```go
jwkSet := &jwk.JWKSet{}

// RSA key for RS256
rsaKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
jwkSet.Add(jwk.FromPublicKey(rsaKey.PublicKey, "sig", "rsa-key"))

// ECDSA key for ES256
ecKey, _ := algo.GenerateECDSAKeyPair(algo.P256)
jwkSet.Add(jwk.FromPublicKey(ecKey.PublicKey, "sig", "ec-key"))

// Ed25519 key for EdDSA
edKey, _ := algo.GenerateEd25519KeyPair()
jwkSet.Add(jwk.FromPublicKey(edKey.PublicKey, "sig", "ed-key"))

// Clients can choose preferred algorithm
```

### 4. Cross-Platform Key Exchange

Export keys for use in other systems:

```go
// Export GoPKI key to JWK for JavaScript client
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "server-key")
jwkJSON, _ := jwkKey.Marshal()

// JavaScript can import this JWK using Web Crypto API:
// const publicKey = await crypto.subtle.importKey(
//   "jwk", jwkData, {name: "ECDSA", namedCurve: "P-256"}, true, ["verify"]
// )
```

## Error Handling

```go
var (
    ErrInvalidKeyType       = errors.New("invalid or unsupported key type")
    ErrInvalidJWK           = errors.New("invalid JWK format")
    ErrKeyNotFound          = errors.New("key not found")
    ErrMissingRequiredField = errors.New("missing required JWK field")
    ErrInvalidCurve         = errors.New("invalid or unsupported elliptic curve")
)
```

**Example:**

```go
jwkKey, err := jwk.Parse(data)
if err != nil {
    if errors.Is(err, jwk.ErrMissingRequiredField) {
        // Handle missing field error
    } else if errors.Is(err, jwk.ErrInvalidKeyType) {
        // Handle invalid key type
    }
}
```

## Security Considerations

### 1. Public Keys Only

This implementation focuses on **public key JWKs**. Private key material is not exported:

```go
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "key-1")
println(jwkKey.IsPrivate()) // false - no private exponent exported
```

### 2. Coordinate Padding

ECDSA coordinates are properly padded to prevent timing attacks:

```go
// P-256 coordinates are always 32 bytes
// P-384 coordinates are always 48 bytes
// P-521 coordinates are always 66 bytes
```

### 3. Curve Validation

EC points are validated to be on the specified curve:

```go
publicKey, err := jwkKey.ToPublicKey()
// Returns error if point not on curve
```

### 4. Key Size Validation

Ed25519 public keys must be exactly 32 bytes:

```go
// Invalid size returns error
if len(edKey) != ed25519.PublicKeySize {
    return nil, fmt.Errorf("invalid Ed25519 public key size")
}
```

## Testing

```bash
# Run tests
go test ./jose/jwk

# Run with coverage
go test -coverprofile=coverage.out ./jose/jwk
go tool cover -html=coverage.out
```

**Test Coverage:** 79.6%

## Integration with Other JOSE Modules

### With JWT

```go
// Publish verification keys for JWT
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "jwt-key")

// Create JWT
token, _ := jwt.Sign(claims, keyPair, "RS256", "jwt-key")

// Clients fetch JWK and verify
```

### With JWS

```go
// Export signing key
jwkKey, _ := jwk.FromGoPKIKeyPair(keyPair, "sig", "jws-key")

// Create detached JWS
signature, _ := jws.SignDetached(payload, keyPair, "ES256", "jws-key")

// Publish JWK for verification
```

## Standards Compliance

- [RFC 7517](https://tools.ietf.org/html/rfc7517): JSON Web Key (JWK)
- [RFC 7518](https://tools.ietf.org/html/rfc7518): JSON Web Algorithms (JWA)
- [RFC 8037](https://tools.ietf.org/html/rfc8037): CFRG Elliptic Curve Algorithms

## Limitations

1. **Public keys only**: Private key export not supported (by design for security)
2. **No symmetric keys**: oct (symmetric) keys not implemented in this phase
3. **No X.509 chain**: x5c/x5t parameters not supported
4. **No key operations**: key_ops validation not enforced

## Related Packages

- [`jose/jwt`](../jwt/README.md): JSON Web Token implementation
- [`jose/jws`](../jws/README.md): JSON Web Signature implementation
- [`jose/jwe`](../jwe/README.md): JSON Web Encryption implementation
- [`keypair`](../../keypair/README.md): Type-safe key pair generation

## License

Same as GoPKI project.
