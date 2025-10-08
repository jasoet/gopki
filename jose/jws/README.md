# JWS (JSON Web Signature) Module

RFC 7515 compliant JSON Web Signature implementation with comprehensive algorithm support.

## Overview

The JWS module provides digital signature capabilities for JSON data and arbitrary payloads. It supports three serialization formats (Compact, JSON, Detached) and all standard signing algorithms including RSA, ECDSA, Ed25519, and HMAC.

**Key Features:**
- ✅ RFC 7515 compliant
- ✅ Compact, JSON, and Detached serialization formats
- ✅ Multi-signature support (JSON format)
- ✅ All standard algorithms (RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, HS256/384/512)
- ✅ Type-safe API using Go generics
- ✅ Detached content for large payloads
- ✅ 81% test coverage

## Quick Start

### Compact Serialization (Single Signature)

```go
package main

import (
    "fmt"
    "crypto/rsa"
    "github.com/jasoet/gopki/jose/jws"
    "github.com/jasoet/gopki/jose/jwt"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA key pair
    keyPair, _ := algo.GenerateRSAKeyPair(2048)

    // Sign JSON payload
    payload := []byte(`{"message": "Hello, JWS!"}`)
    token, _ := jws.SignCompact(payload, keyPair.Private, jwt.RS256, "key-1")

    // Verify and extract payload
    verified, _ := jws.VerifyCompact(token, keyPair.Public, jwt.RS256)
    fmt.Println(string(verified)) // {"message": "Hello, JWS!"}
}
```

### HMAC Signing (Symmetric Key)

```go
secret := []byte("my-secret-key-at-least-32-bytes-long")

// Sign
token, _ := jws.SignCompactWithSecret(payload, secret, jwt.HS256)

// Verify
verified, _ := jws.VerifyCompactWithSecret(token, secret, jwt.HS256)
```

### JSON Serialization (Multiple Signatures)

```go
// Create multiple signers
signers := []*jws.Signer{
    {
        Key:       rsaPrivate,
        Algorithm: jwt.RS256,
        KeyID:     "rsa-key-1",
    },
    {
        Key:       ecdsaPrivate,
        Algorithm: jwt.ES256,
        KeyID:     "ec-key-1",
    },
}

// Sign with multiple keys
token, _ := jws.SignJSON(payload, signers)

// Verify - at least one signature must be valid
verifiers := []*jws.Verifier{
    {Key: rsaPublic, Algorithm: jwt.RS256, KeyID: "rsa-key-1"},
}
verified, _ := jws.VerifyJSON(token, verifiers)
```

### Detached Content (Large Payloads)

```go
// Large content transmitted separately
content := []byte("very large file content...")

// Sign (creates header..signature format)
detachedJWS, _ := jws.SignDetached(content, privateKey, jwt.RS256, "key-1")

// Transmit detachedJWS and content separately

// Verify with content
err := jws.VerifyDetached(detachedJWS, content, publicKey, jwt.RS256)
```

## Serialization Formats

### 1. Compact Serialization

Format: `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`

**Use cases:**
- Single signature
- HTTP Authorization headers
- URL-safe tokens
- JWT compatibility

**Functions:**
- `SignCompact[K keypair.PrivateKey](payload, key, alg, keyID) (string, error)`
- `VerifyCompact[K keypair.PublicKey](jws, key, expectedAlg) ([]byte, error)`
- `SignCompactWithSecret(payload, secret, alg) (string, error)`
- `VerifyCompactWithSecret(jws, secret, expectedAlg) ([]byte, error)`

### 2. JSON Serialization

Format:
```json
{
  "payload": "BASE64URL(payload)",
  "signatures": [
    {
      "protected": "BASE64URL(header)",
      "header": {...},
      "signature": "BASE64URL(signature)"
    }
  ]
}
```

**Use cases:**
- Multiple signatures on same payload
- Different keys/algorithms per signature
- Unprotected header parameters
- Advanced scenarios

**Functions:**
- `SignJSON(payload, signers) (*JSONSerialization, error)`
- `VerifyJSON(jws, verifiers) ([]byte, error)`
- `UnmarshalJSON(data) (*JSONSerialization, error)`

### 3. Detached Content

Format: `BASE64URL(header)..BASE64URL(signature)` (note double dots)

**Use cases:**
- Large payloads (GBs)
- Payload transmitted separately
- Bandwidth optimization
- External content signing

**Functions:**
- `SignDetached[K keypair.PrivateKey](content, key, alg, keyID) (string, error)`
- `VerifyDetached[K keypair.PublicKey](detachedJWS, content, key, expectedAlg) error`
- `SignDetachedWithSecret(content, secret, alg) (string, error)`
- `VerifyDetachedWithSecret(detachedJWS, content, secret, expectedAlg) error`

## Supported Algorithms

| Algorithm | Type | Key Size | Description |
|-----------|------|----------|-------------|
| RS256     | RSA  | ≥2048 bits | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384     | RSA  | ≥2048 bits | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512     | RSA  | ≥2048 bits | RSASSA-PKCS1-v1_5 with SHA-512 |
| PS256     | RSA  | ≥2048 bits | RSASSA-PSS with SHA-256 |
| PS384     | RSA  | ≥2048 bits | RSASSA-PSS with SHA-384 |
| PS512     | RSA  | ≥2048 bits | RSASSA-PSS with SHA-512 |
| ES256     | ECDSA| P-256 | ECDSA with SHA-256 |
| ES384     | ECDSA| P-384 | ECDSA with SHA-384 |
| ES512     | ECDSA| P-521 | ECDSA with SHA-512 |
| EdDSA     | Ed25519 | - | Ed25519 signature |
| HS256     | HMAC | ≥256 bits | HMAC with SHA-256 |
| HS384     | HMAC | ≥384 bits | HMAC with SHA-384 |
| HS512     | HMAC | ≥512 bits | HMAC with SHA-512 |

## API Reference

### Signer

Multi-signature signer configuration for JSON serialization.

```go
type Signer struct {
    // Key is the private key (can be *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, or []byte for HMAC)
    Key interface{}

    // Algorithm is the signing algorithm
    Algorithm jwt.Algorithm

    // KeyID is optional key identifier (included in protected header)
    KeyID string

    // UnprotectedHeader contains additional unprotected header parameters
    // Example: {"jku": "https://example.com/keys"}
    UnprotectedHeader map[string]interface{}
}
```

### Verifier

Multi-signature verifier configuration for JSON serialization.

```go
type Verifier struct {
    // Key is the public key (can be *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, or []byte for HMAC)
    Key interface{}

    // Algorithm is the expected signing algorithm
    Algorithm jwt.Algorithm

    // KeyID is optional key identifier for matching signatures
    KeyID string
}
```

### JSONSerialization

Represents JWS in JSON serialization format.

```go
type JSONSerialization struct {
    Payload    string          `json:"payload"`
    Signatures []JSONSignature `json:"signatures"`
}

// Methods
func (j *JSONSerialization) Marshal() ([]byte, error)
```

### JSONSignature

Individual signature in JSON serialization.

```go
type JSONSignature struct {
    Protected string                 `json:"protected,omitempty"`
    Header    map[string]interface{} `json:"header,omitempty"`
    Signature string                 `json:"signature"`
}
```

## Error Handling

All JWS errors are defined in `errors.go`:

```go
var (
    ErrInvalidFormat         = errors.New("invalid JWS format")
    ErrInvalidJSON           = errors.New("invalid JWS JSON format")
    ErrNoSignatures          = errors.New("no signatures provided")
    ErrNoValidSignature      = errors.New("no valid signature found")
    ErrInvalidDetachedFormat = errors.New("invalid detached JWS format")
)
```

**Example error handling:**
```go
verified, err := jws.VerifyJSON(token, verifiers)
if err != nil {
    if errors.Is(err, jws.ErrNoValidSignature) {
        // No valid signature found
    }
    return err
}
```

## Advanced Usage

### Multiple Algorithms in JSON Format

```go
// Sign with RSA, ECDSA, and HMAC
signers := []*jws.Signer{
    {Key: rsaPrivate, Algorithm: jwt.RS256, KeyID: "rsa-1"},
    {Key: ecdsaPrivate, Algorithm: jwt.ES256, KeyID: "ec-1"},
    {Key: hmacSecret, Algorithm: jwt.HS256, KeyID: "hmac-1"},
}

token, _ := jws.SignJSON(payload, signers)

// Verify with any one of the keys
verifiers := []*jws.Verifier{
    {Key: rsaPublic, Algorithm: jwt.RS256, KeyID: "rsa-1"},
}
verified, _ := jws.VerifyJSON(token, verifiers) // Succeeds if RSA signature valid
```

### Unprotected Headers

```go
signer := &jws.Signer{
    Key:       privateKey,
    Algorithm: jwt.RS256,
    KeyID:     "key-1",
    UnprotectedHeader: map[string]interface{}{
        "jku": "https://example.com/jwks.json",  // JWK Set URL
        "x5u": "https://example.com/cert.pem",   // X.509 URL
    },
}

token, _ := jws.SignJSON(payload, []*jws.Signer{signer})

// Access unprotected header
fmt.Println(token.Signatures[0].Header["jku"]) // https://example.com/jwks.json
```

### JSON vs Non-JSON Payloads

The module handles both JSON and non-JSON payloads automatically:

```go
// JSON payload - stored directly
jsonPayload := []byte(`{"user": "alice"}`)
token1, _ := jws.SignCompact(jsonPayload, key, jwt.RS256, "")

// Non-JSON payload - wrapped internally as {"data": payload}
textPayload := []byte("Hello, World!")
token2, _ := jws.SignCompact(textPayload, key, jwt.RS256, "")

// Verification returns original payload in both cases
verified1, _ := jws.VerifyCompact(token1, pubKey, jwt.RS256) // {"user": "alice"}
verified2, _ := jws.VerifyCompact(token2, pubKey, jwt.RS256) // Hello, World!
```

## Relationship with JWT

**JWS is the foundation of JWT**:
- JWT uses JWS Compact Serialization exclusively
- JWT adds Claims structure on top of JWS
- JWS can sign any payload, not just JWT claims

```
JWT = JWS Compact + Claims Validation
```

**Use JWT when:**
- You need claims-based tokens (exp, iss, aud, etc.)
- Building authentication/authorization
- Standard token validation

**Use JWS directly when:**
- Signing arbitrary JSON/data
- Need multiple signatures (JSON format)
- Detached content for large files
- More control over payload structure

## Security Considerations

### Algorithm Selection

- **RS256**: Most widely supported, good default
- **PS256**: More secure than RS256, use if supported
- **ES256**: Smaller signatures, faster, use if supported
- **EdDSA**: Best performance, use Ed25519 keys if possible
- **HS256**: Symmetric, use only for trusted parties

### Key Management

```go
// ❌ DON'T: Hardcode secrets
secret := []byte("secret123")

// ✅ DO: Load from secure storage
secret := loadFromKeyVault("hmac-key-id")

// ❌ DON'T: Reuse same key for signing and encryption
key := loadKey("shared-key")

// ✅ DO: Use different keys for different purposes
signingKey := loadKey("signing-key-id")
encryptionKey := loadKey("encryption-key-id")
```

### Algorithm Confusion

The module prevents algorithm confusion attacks:

```go
// ✅ Algorithm is verified during signature verification
verified, err := jws.VerifyCompact(token, pubKey, jwt.RS256)
if err != nil {
    // Signature invalid OR algorithm mismatch
}

// If token was signed with HS256 but verified with RS256, it fails
```

### Key ID Matching

```go
// Use KeyID to match correct verifier
verifiers := []*jws.Verifier{
    {Key: key1, Algorithm: jwt.RS256, KeyID: "key-1"},
    {Key: key2, Algorithm: jwt.RS256, KeyID: "key-2"},
}

// Only signatures with matching KeyID are verified
verified, _ := jws.VerifyJSON(token, verifiers)
```

## Testing

Run tests:
```bash
# Unit tests
go test ./jose/jws/

# With coverage
go test -coverprofile=coverage.out ./jose/jws/
go tool cover -html=coverage.out

# With race detection
go test -race ./jose/jws/
```

Current coverage: **81.0%** (exceeds GoPKI 80% target)

## Performance

Benchmark results (2048-bit RSA, P-256 ECDSA):

| Operation | Algorithm | Time/op | Allocations |
|-----------|-----------|---------|-------------|
| Sign      | RS256     | ~1.2ms  | ~50 allocs  |
| Sign      | ES256     | ~300μs  | ~30 allocs  |
| Sign      | EdDSA     | ~100μs  | ~20 allocs  |
| Sign      | HS256     | ~5μs    | ~10 allocs  |
| Verify    | RS256     | ~100μs  | ~20 allocs  |
| Verify    | ES256     | ~500μs  | ~30 allocs  |
| Verify    | EdDSA     | ~150μs  | ~15 allocs  |
| Verify    | HS256     | ~5μs    | ~10 allocs  |

**Recommendations:**
- Use EdDSA (Ed25519) for best performance
- Use ES256 for good balance of security and speed
- Use HS256 for symmetric scenarios (fastest)
- Avoid RS256 for high-throughput scenarios

## Integration with GoPKI

### Using with `keypair` Module

```go
import (
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/jose/jws"
    "github.com/jasoet/gopki/jose/jwt"
)

// Generate type-safe key pairs
rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
edKeys, _ := algo.GenerateEd25519KeyPair()

// Use with JWS (type-safe!)
jws.SignCompact(payload, rsaKeys.Private, jwt.RS256, "")
jws.SignCompact(payload, ecKeys.Private, jwt.ES256, "")
jws.SignCompact(payload, edKeys.Private, jwt.EdDSA, "")
```

### Using with `signing` Module

For CMS/PKCS#7 signatures, use the `signing` module. For JWT/JWS, use this module.

```go
// JWS for JSON/web scenarios
jwsToken, _ := jws.SignCompact(payload, key, jwt.RS256, "")

// CMS for document signing
import "github.com/jasoet/gopki/signing"
cmsSignature, _ := signing.Sign(document, key, opts)
```

## Examples

See test file `jws_test.go` for comprehensive examples:

- `TestCompactSignVerify`: Compact serialization with RS256, ES256, EdDSA
- `TestCompactWithHMAC`: HMAC signing
- `TestJSONSerialization`: Multiple signatures
- `TestJSONSerializationWithOneVerifier`: Partial verification
- `TestDetachedContent`: Detached payload
- `TestMixedAlgorithmsJSON`: Multiple algorithms in one JWS
- `TestUnprotectedHeader`: Unprotected header parameters

## Limitations

1. **No Flattened JSON Format**: Only general JSON serialization is supported
2. **No Critical Headers**: The `crit` header parameter is not validated
3. **Key Size Constraints**: Follows GoPKI standards (RSA ≥2048 bits)

## References

- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

## License

Part of the GoPKI project. See main repository for license information.
