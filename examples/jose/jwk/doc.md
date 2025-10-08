# JWK (JSON Web Key) Examples

Comprehensive examples demonstrating all features of the GoPKI JWK module.

## Overview

This example demonstrates:
- Export GoPKI keys to JWK format
- Import JWK format to GoPKI keys
- JWK Sets (JWKS) management
- Key rotation strategies
- OIDC discovery endpoint
- Multi-algorithm support

## Running the Example

```bash
# From repository root
go run -tags example ./examples/jose/jwk/

# Or use Task
task examples:jose:jwk
```

## What's Demonstrated

### Part 1: JWK Export
Convert GoPKI/stdlib keys to JWK format:
- RSA (2048-bit modulus and exponent)
- ECDSA (P-256, P-384, P-521 curves)
- Ed25519 (Octet Key Pair)

### Part 2: JWK Import
Parse JWK JSON and convert to GoPKI keys:
- Round-trip verification (export → import)
- Type-safe conversion to Go standard library keys

### Part 3: JWK Sets (JWKS)
Manage collections of keys:
- Add/remove keys
- Find by key ID
- Find by use (sig/enc)

### Part 4: Key Rotation
Zero-downtime key rotation strategy:
- Add new key while keeping old
- Grace period with both keys active
- Remove old key after migration

### Part 5: Real-World Use Cases
- **OIDC Discovery**: Publishing JWKS for OAuth/OIDC
- **Multi-Algorithm**: Supporting different client capabilities

## Output Files

```
output/
├── jwk_rsa_public.json              # RSA public key
├── jwk_ec_p256_public.json          # ECDSA P-256 key
├── jwk_ec_p384_public.json          # ECDSA P-384 key
├── jwk_ec_p521_public.json          # ECDSA P-521 key
├── jwk_ed25519_public.json          # Ed25519 key
├── jwks_example.json                # JWK Set example
├── jwks_rotation.json               # Key rotation JWKS
├── jwks_oidc_discovery.json         # OIDC discovery endpoint
└── jwks_multi_algorithm.json        # Multi-algorithm JWKS
```

## Key Concepts

### JWK Structure

**RSA Public Key:**
```json
{
  "kty": "RSA",
  "use": "sig",
  "kid": "rsa-2024-10",
  "n": "0vx7agoebGcQSuuPiLJXZ...",  // Modulus (base64url)
  "e": "AQAB"                        // Exponent (base64url)
}
```

**ECDSA Public Key:**
```json
{
  "kty": "EC",
  "use": "sig",
  "kid": "ec-2024-10",
  "crv": "P-256",                    // Curve name
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHM...", // X coordinate
  "y": "x_FEzRu9m36HLN_tue659LNpXW..." // Y coordinate
}
```

**Ed25519 Public Key:**
```json
{
  "kty": "OKP",
  "use": "sig",
  "kid": "ed-2024-10",
  "crv": "Ed25519",                  // Curve name
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" // Public key bytes
}
```

### JWK Set (JWKS)

Collection of JWKs:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "rsa-key-1",
      "use": "sig",
      ...
    },
    {
      "kty": "EC",
      "kid": "ec-key-1",
      "use": "sig",
      ...
    }
  ]
}
```

## Key Rotation Strategy

### Zero-Downtime Rotation

```
Timeline:
┌─────────────────────────────────────────────────────────┐
│ Day 0: Add new key (2024-11)                            │
│        JWKS: [2024-10, 2024-11]                         │
│        - Issue tokens: Use 2024-11                      │
│        - Verify tokens: Accept both                     │
├─────────────────────────────────────────────────────────┤
│ Day 1-30: Grace period                                  │
│          JWKS: [2024-10, 2024-11]                       │
│          - All clients fetch updated JWKS               │
│          - Old tokens (2024-10) still valid             │
├─────────────────────────────────────────────────────────┤
│ Day 31: Remove old key (2024-10)                        │
│         JWKS: [2024-11]                                 │
│         - All clients using new key                     │
└─────────────────────────────────────────────────────────┘
```

### Implementation

```go
// Step 1: Add new key
jwkSet.Add(newKey)  // JWKS now has [old, new]

// Step 2: Wait for grace period (e.g., 30 days)
// All clients fetch updated JWKS

// Step 3: Remove old key
jwkSet.Remove("old-key-id")  // JWKS now has [new]
```

## OIDC Discovery Pattern

### Provider Setup

```go
// Create JWKS with current and previous keys
jwkSet := &jwk.JWKSet{}
jwkSet.Add(currentKey)   // Active signing key
jwkSet.Add(previousKey)  // For validation during rotation

// Publish at /.well-known/jwks.json
http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
    json, _ := jwkSet.Marshal()
    w.Header().Set("Content-Type", "application/json")
    w.Write(json)
})
```

### Client Usage

```go
// 1. Fetch JWKS from discovery endpoint
resp, _ := http.Get("https://auth.example.com/.well-known/jwks.json")
jwkSet, _ := jwk.ParseSet(resp.Body)

// 2. Extract kid from JWT header
kid := jwtHeader["kid"]

// 3. Find matching key
signingKey, _ := jwkSet.FindByKeyID(kid)

// 4. Verify JWT
publicKey, _ := signingKey.ToPublicKey()
claims, _ := jwt.Verify(token, publicKey)
```

## Multi-Algorithm Support

### Why Support Multiple Algorithms?

1. **Compatibility**: Legacy clients may only support RSA
2. **Performance**: Modern clients benefit from ECDSA/Ed25519
3. **Security**: Different security requirements
4. **Migration**: Gradual algorithm upgrades

### Implementation

```go
jwkSet := &jwk.JWKSet{}

// RSA for compatibility
jwkSet.Add(rsaKey)   // kid: "rsa-compat"

// ECDSA for modern clients
jwkSet.Add(ecKey)    // kid: "ec-modern"

// Ed25519 for high security
jwkSet.Add(edKey)    // kid: "ed-secure"

// Client requests token with preferred algorithm
// Server signs with corresponding key
```

## Use Case Patterns

### 1. Public Key Distribution

**Scenario**: Distribute public keys for JWT verification

```go
// Generate signing keys
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// Export to JWK
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "api-key-1")

// Publish
jsonBytes, _ := jwkKey.Marshal()
// Serve at /.well-known/jwks.json
```

### 2. Key Discovery

**Scenario**: Find specific key in JWKS by ID or use

```go
// Load JWKS
jwkSet, _ := jwk.ParseSet(jwksBytes)

// Find specific key
signingKey, _ := jwkSet.FindByKeyID("rsa-2024-10")

// Find all signature keys
sigKeys := jwkSet.FindByUse("sig")

// Find all encryption keys
encKeys := jwkSet.FindByUse("enc")
```

### 3. Cross-Platform Key Exchange

**Scenario**: Export keys for JavaScript Web Crypto API

```go
// Export GoPKI key to JWK
jwkKey, _ := jwk.FromPublicKey(publicKey, "sig", "my-key")
jsonBytes, _ := jwkKey.Marshal()

// JavaScript can import:
// const key = await crypto.subtle.importKey(
//   "jwk", jwkData,
//   {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"},
//   true, ["verify"]
// )
```

## Algorithm Selection Guide

| Use Case | Algorithm | JWK kty | Reason |
|----------|-----------|---------|--------|
| Legacy compatibility | RSA 2048 | RSA | Universal support |
| Modern web apps | ECDSA P-256 | EC | Smaller keys, fast |
| High security | Ed25519 | OKP | Fastest, most secure |
| IoT devices | ECDSA P-256 | EC | Low power consumption |

## Security Considerations

### Public Keys Only

JWK export only includes public key material:
- No private exponents
- No private keys
- Safe for distribution

### Coordinate Padding

ECDSA coordinates are properly padded:
- P-256: 32 bytes
- P-384: 48 bytes
- P-521: 66 bytes

### Curve Validation

EC points are validated:
- Point must be on specified curve
- Prevents invalid point attacks

## Performance

**Export (GoPKI → JWK):**
- RSA: ~10,000 ops/sec
- ECDSA: ~50,000 ops/sec
- Ed25519: ~100,000 ops/sec

**Import (JWK → GoPKI):**
- RSA: ~10,000 ops/sec
- ECDSA: ~20,000 ops/sec (includes curve validation)
- Ed25519: ~100,000 ops/sec

## Example Code Snippets

### Basic Export

```go
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "my-key-1")
jsonBytes, _ := jwkKey.MarshalIndent("", "  ")
```

### Basic Import

```go
jwkKey, _ := jwk.Parse(jwkJSON)
publicKey, _ := jwkKey.ToPublicKey()
rsaKey := publicKey.(*rsa.PublicKey) // Type assertion
```

### JWKS Management

```go
jwkSet := &jwk.JWKSet{}

// Add keys
jwkSet.Add(key1)
jwkSet.Add(key2)

// Find
foundKey, _ := jwkSet.FindByKeyID("key-1")

// Remove
jwkSet.Remove("old-key")

// Save
jsonBytes, _ := jwkSet.Marshal()
```

## Integration with Other JOSE Modules

### With JWT

```go
// 1. Sign JWT
token, _ := jwt.Sign(claims, keyPair, "RS256", "rsa-key-1")

// 2. Export public key as JWK
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "rsa-key-1")

// 3. Publish JWK
// Client fetches JWK and verifies JWT
```

### With JWS

```go
// Sign document
signature, _ := jws.SignCompact(document, keyPair, "ES256", "ec-key-1")

// Export verification key
jwkKey, _ := jwk.FromPublicKey(keyPair.PublicKey, "sig", "ec-key-1")
```

## Standards Compliance

- [RFC 7517](https://tools.ietf.org/html/rfc7517): JSON Web Key (JWK)
- [RFC 7518](https://tools.ietf.org/html/rfc7518): JSON Web Algorithms (JWA)
- [RFC 8037](https://tools.ietf.org/html/rfc8037): CFRG Elliptic Curve Algorithms

## Related Documentation

- [JWK Module README](../../../jose/jwk/README.md)
- [JWT Examples](../jwt/doc.md)
- [RFC 7517 - JWK](https://tools.ietf.org/html/rfc7517)
