# JWT (JSON Web Token) Module

[![Go Reference](https://pkg.go.dev/badge/github.com/jasoet/gopki/jose/jwt.svg)](https://pkg.go.dev/github.com/jasoet/gopki/jose/jwt)
[![Test Coverage](https://img.shields.io/badge/coverage-88.0%25-brightgreen)](https://github.com/jasoet/gopki)

Full JWT implementation for GoPKI with support for all major signing algorithms (RSA, ECDSA, Ed25519, HMAC) and comprehensive claims validation.

## Features

✅ **RFC 7519 Compliant** - Full JWT specification support
✅ **Multiple Algorithms** - RS256/384/512, ES256/384/512, EdDSA, HS256/384/512, PS256/384/512
✅ **Security Hardened** - Algorithm confusion prevention, 'none' algorithm rejection
✅ **Claims Validation** - Expiration, not-before, issuer, audience validation
✅ **Type Safe** - Leverages GoPKI's generic type constraints
✅ **Zero Dependencies** - Uses stdlib + existing GoPKI infrastructure
✅ **88% Test Coverage** - Comprehensive test suite with security tests

## Quick Start

### Installation

```bash
go get github.com/jasoet/gopki/jose/jwt
```

### Basic Usage

#### Sign with RSA

```go
import (
    "time"
    "github.com/jasoet/gopki/jose/jwt"
)

// Create claims
claims := jwt.NewClaims()
claims.Subject = "user123"
claims.Issuer = "https://auth.example.com"
claims.Audience = []string{"https://api.example.com"}
claims.SetExpiration(24 * time.Hour)

// Sign with RSA private key
token, err := jwt.Sign(claims, rsaPrivateKey, jwt.RS256, jwt.DefaultSignOptions())
if err != nil {
    log.Fatal(err)
}

fmt.Println(token)
// Output: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwi...
```

#### Verify JWT

```go
opts := jwt.DefaultVerifyOptions()
opts.ExpectedAlgorithm = jwt.RS256 // Prevent algorithm confusion
opts.Validation.ValidateIssuer = true
opts.Validation.ExpectedIssuer = "https://auth.example.com"

verified, err := jwt.Verify(token, rsaPublicKey, opts)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Subject: %s\n", verified.Subject)
```

#### Sign with HMAC (HS256)

```go
secret := []byte("your-256-bit-secret")

claims := jwt.NewClaims()
claims.Subject = "user456"
claims.SetExpiration(time.Hour)

token, err := jwt.SignWithSecret(claims, secret, jwt.HS256)
if err != nil {
    log.Fatal(err)
}

// Verify
verified, err := jwt.VerifyWithSecret(token, secret, jwt.DefaultVerifyOptions())
```

#### Sign with ECDSA

```go
// ES256 (ECDSA P-256 + SHA-256)
token, err := jwt.Sign(claims, ecdsaPrivateKey, jwt.ES256, jwt.DefaultSignOptions())

// Verify
verified, err := jwt.Verify(token, ecdsaPublicKey, jwt.DefaultVerifyOptions())
```

#### Sign with Ed25519

```go
token, err := jwt.Sign(claims, ed25519PrivateKey, jwt.EdDSA, jwt.DefaultSignOptions())

verified, err := jwt.Verify(token, ed25519PublicKey, jwt.DefaultVerifyOptions())
```

## Advanced Usage

### Custom Claims

```go
claims := jwt.NewClaims()
claims.Subject = "user123"
claims.Extra["role"] = "admin"
claims.Extra["permissions"] = []string{"read", "write", "delete"}
claims.Extra["tenant_id"] = "acme-corp"

token, _ := jwt.Sign(claims, key, jwt.RS256, nil)

// After verification
verified, _ := jwt.Verify(token, publicKey, nil)
role := verified.Extra["role"].(string)
```

### Key ID (for Key Rotation)

```go
opts := jwt.DefaultSignOptions()
opts.KeyID = "2024-key-1"

token, err := jwt.Sign(claims, privateKey, jwt.RS256, opts)

// Parse to check header
parsed, _ := jwt.Parse(token)
fmt.Println(parsed.Header.KeyID) // "2024-key-1"
```

### RSA-PSS Signing

```go
opts := jwt.DefaultSignOptions()
opts.UsePSS = true

token, err := jwt.Sign(claims, rsaPrivateKey, jwt.PS256, opts)
```

### Claims Validation

```go
opts := jwt.DefaultVerifyOptions()

// Validate expiration and not-before (enabled by default)
opts.Validation.ValidateExpiry = true
opts.Validation.ValidateNotBefore = true

// Validate issuer
opts.Validation.ValidateIssuer = true
opts.Validation.ExpectedIssuer = "https://auth.example.com"

// Validate audience
opts.Validation.ValidateAudience = true
opts.Validation.ExpectedAudience = []string{"https://api.example.com"}

// Clock skew tolerance
opts.Validation.ClockSkew = 60 * time.Second

verified, err := jwt.Verify(token, publicKey, opts)
```

### Parse Without Verification

```go
// Parse token structure without verifying signature
token, err := jwt.Parse(tokenString)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Algorithm: %s\n", token.Header.Algorithm)
fmt.Printf("Subject: %s\n", token.Claims.Subject)
fmt.Printf("Expires: %d\n", token.Claims.ExpiresAt)
```

## Supported Algorithms

| Algorithm | Type | Description | Hash |
|-----------|------|-------------|------|
| **RS256** | RSA | PKCS#1 v1.5 + SHA-256 | SHA-256 |
| **RS384** | RSA | PKCS#1 v1.5 + SHA-384 | SHA-384 |
| **RS512** | RSA | PKCS#1 v1.5 + SHA-512 | SHA-512 |
| **PS256** | RSA-PSS | Probabilistic Signature + SHA-256 | SHA-256 |
| **PS384** | RSA-PSS | Probabilistic Signature + SHA-384 | SHA-384 |
| **PS512** | RSA-PSS | Probabilistic Signature + SHA-512 | SHA-512 |
| **ES256** | ECDSA | P-256 curve + SHA-256 | SHA-256 |
| **ES384** | ECDSA | P-384 curve + SHA-384 | SHA-384 |
| **ES512** | ECDSA | P-521 curve + SHA-512 | SHA-512 |
| **EdDSA** | Ed25519 | Edwards-curve DSA | - |
| **HS256** | HMAC | HMAC + SHA-256 | SHA-256 |
| **HS384** | HMAC | HMAC + SHA-384 | SHA-384 |
| **HS512** | HMAC | HMAC + SHA-512 | SHA-512 |

### Algorithm Recommendations

**For Asymmetric Keys:**
1. **ES256** - Fast, small signatures, modern
2. **EdDSA** - Fastest, smallest keys, constant-time
3. **RS256** - Widely supported, good compatibility

**For Symmetric Keys:**
1. **HS256** - Fast, simple, shared secret required

⚠️ **Never use** `none` algorithm - always rejected for security

## Security Features

### 1. Algorithm Confusion Prevention

```go
// Always specify expected algorithm
opts := &jwt.VerifyOptions{
    ExpectedAlgorithm: jwt.RS256, // Rejects if different
}

verified, err := jwt.Verify(token, key, opts)
```

### 2. 'none' Algorithm Rejection

```go
// Automatically rejected during parsing
token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0."
_, err := jwt.Parse(token)
// Returns: ErrAlgorithmNone
```

### 3. Token Size Limits

```go
// Tokens > 8KB automatically rejected (DoS prevention)
const MaxTokenSize = 8192
```

### 4. Constant-Time HMAC Comparison

```go
// Uses hmac.Equal for timing attack resistance
return hmac.Equal(signature, expectedMAC)
```

### 5. Clock Skew Tolerance

```go
opts.Validation.ClockSkew = 60 * time.Second // Default
```

## Error Handling

All errors are predefined for easy checking:

```go
import "errors"

_, err := jwt.Verify(token, key, opts)

if errors.Is(err, jwt.ErrTokenExpired) {
    // Token expired
} else if errors.Is(err, jwt.ErrInvalidSignature) {
    // Signature verification failed
} else if errors.Is(err, jwt.ErrAlgorithmMismatch) {
    // Algorithm doesn't match expected
} else if errors.Is(err, jwt.ErrInvalidIssuer) {
    // Issuer validation failed
}
```

### Error Types

- `ErrInvalidTokenFormat` - Malformed token structure
- `ErrInvalidSignature` - Signature verification failed
- `ErrTokenExpired` - Token has expired
- `ErrTokenNotYetValid` - Token not yet valid (nbf)
- `ErrInvalidIssuer` - Issuer mismatch
- `ErrInvalidAudience` - Audience mismatch
- `ErrAlgorithmMismatch` - Algorithm doesn't match expected
- `ErrAlgorithmNone` - 'none' algorithm not allowed
- `ErrTokenTooLarge` - Token exceeds size limit
- `ErrUnsupportedAlgorithm` - Algorithm not supported
- `ErrInvalidKey` - Key type invalid for algorithm

## Integration with GoPKI

This module integrates seamlessly with GoPKI's type-safe key management:

```go
import (
    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/jose/jwt"
)

// Generate RSA key pair using GoPKI
rsaKeyPair, err := algo.GenerateRSAKeyPair(2048)

// Sign JWT
token, err := jwt.Sign(claims, rsaKeyPair.PrivateKey, jwt.RS256, nil)

// Verify JWT
verified, err := jwt.Verify(token, rsaKeyPair.PublicKey, nil)
```

## Performance

Typical performance on modern hardware:

| Operation | Algorithm | Time |
|-----------|-----------|------|
| Sign | RS256 (RSA-2048) | ~1ms |
| Verify | RS256 (RSA-2048) | ~1ms |
| Sign | ES256 (ECDSA P-256) | ~0.5ms |
| Verify | ES256 (ECDSA P-256) | ~1ms |
| Sign | EdDSA (Ed25519) | ~0.1ms |
| Verify | EdDSA (Ed25519) | ~0.2ms |
| Sign | HS256 (HMAC) | ~0.05ms |
| Verify | HS256 (HMAC) | ~0.05ms |

## OAuth2 / OpenID Connect Example

```go
// Create ID Token (OpenID Connect)
claims := jwt.NewClaims()
claims.Issuer = "https://auth.example.com"
claims.Subject = userID
claims.Audience = []string{clientID}
claims.IssuedAt = time.Now().Unix()
claims.SetExpiration(15 * time.Minute)
claims.Extra["nonce"] = nonce
claims.Extra["email"] = user.Email
claims.Extra["email_verified"] = true

token, err := jwt.Sign(claims, oidcPrivateKey, jwt.ES256, &jwt.SignOptions{
    KeyID: "2024-key-1",
})

// Verification by client
opts := jwt.DefaultVerifyOptions()
opts.ExpectedAlgorithm = jwt.ES256
opts.Validation.ValidateIssuer = true
opts.Validation.ExpectedIssuer = "https://auth.example.com"
opts.Validation.ValidateAudience = true
opts.Validation.ExpectedAudience = []string{clientID}

verified, err := jwt.Verify(token, oidcPublicKey, opts)
```

## Testing

Run the test suite:

```bash
# Run all tests
go test ./jose/jwt/

# With coverage
go test -coverprofile=coverage.out ./jose/jwt/
go tool cover -html=coverage.out

# With race detection
go test -race ./jose/jwt/
```

Current test coverage: **88.0%**

## RFC Compliance

- ✅ [RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)
- ✅ [RFC 7518](https://tools.ietf.org/html/rfc7518) - JSON Web Algorithms (JWA)
- ✅ [RFC 8032](https://tools.ietf.org/html/rfc8032) - EdDSA (Ed25519)

## License

Part of [GoPKI](https://github.com/jasoet/gopki) - See project LICENSE
