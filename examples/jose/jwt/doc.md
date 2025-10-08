# JWT (JSON Web Token) Examples

Comprehensive examples demonstrating all features of the GoPKI JWT module.

## Overview

This example demonstrates:
- All signature algorithms (RSA, ECDSA, Ed25519, HMAC)
- Claims validation and security features
- Real-world use cases (API authentication, service-to-service)

## Running the Example

```bash
# From repository root
go run -tags example ./examples/jose/jwt/

# Or use Task
task examples:jose:jwt
```

## What's Demonstrated

### Part 1: RSA Signature Algorithms
- **RS256**: RSASSA-PKCS1-v1_5 with SHA-256
- **RS384**: RSASSA-PKCS1-v1_5 with SHA-384
- **RS512**: RSASSA-PKCS1-v1_5 with SHA-512

### Part 2: ECDSA Signature Algorithms
- **ES256**: ECDSA with P-256 and SHA-256
- **ES384**: ECDSA with P-384 and SHA-384
- **ES512**: ECDSA with P-521 and SHA-512

### Part 3: Ed25519 Signature
- **EdDSA**: Ed25519 signature (fastest and most secure)

### Part 4: HMAC Symmetric Signatures
- **HS256**: HMAC with SHA-256
- **HS384**: HMAC with SHA-384
- **HS512**: HMAC with SHA-512

### Part 5: Claims Validation
- Expired token detection
- Not-yet-valid token rejection
- Issuer validation
- Audience validation
- Clock skew tolerance

### Part 6: Real-World Use Cases
- **API Authentication**: User login → JWT issuance → API request validation
- **Service-to-Service**: Microservices authentication using shared HMAC secret

## Output Files

The example generates JWT tokens in `output/` directory:

```
output/
├── jwt_rs256.txt          # RS256 signed token
├── jwt_rs384.txt          # RS384 signed token
├── jwt_rs512.txt          # RS512 signed token
├── jwt_es256.txt          # ES256 signed token
├── jwt_es384.txt          # ES384 signed token
├── jwt_es512.txt          # ES512 signed token
├── jwt_eddsa.txt          # EdDSA signed token
├── jwt_hs256.txt          # HS256 signed token
└── jwt_api_access_token.txt  # Sample API token
```

## Key Takeaways

### Algorithm Selection Guide

| Use Case | Recommended Algorithm | Reason |
|----------|----------------------|--------|
| API Authentication | RS256 or ES256 | Public key verification, widely supported |
| High Security | EdDSA | Fastest, most secure, no side-channels |
| Service Mesh | HS256 | Fast, simple, shared secret |
| Legacy Systems | RS256 | Maximum compatibility |

### Security Best Practices

1. **Always validate expiry** (`RequireExpiry: true`)
2. **Use clock skew** (60 seconds recommended)
3. **Validate issuer and audience** for multi-tenant systems
4. **Use strong secrets** for HMAC (minimum 32 bytes)
5. **Short expiry times** (1-24 hours for users, 5-15 minutes for services)

### Common Claims

```go
type Claims struct {
    Issuer    string    // "iss" - who issued the token
    Subject   string    // "sub" - user/service identifier
    Audience  Audience  // "aud" - intended recipient(s)
    ExpiresAt int64     // "exp" - expiry timestamp
    NotBefore int64     // "nbf" - not valid before
    IssuedAt  int64     // "iat" - issuance timestamp
    ID        string    // "jti" - unique token ID
    Custom    map[string]interface{} // Custom claims
}
```

## Example Code Snippets

### Basic Token Creation and Verification

```go
// Create claims
claims := jwt.Claims{
    Issuer:    "auth.example.com",
    Subject:   "user-123",
    Audience:  jwt.Audience{"app"},
    ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
}

// Sign with RSA
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
token, _ := jwt.Sign(claims, keyPair, "RS256", "key-id")

// Verify
verifiedClaims, err := jwt.Verify(token, keyPair)
```

### Validation with Options

```go
opts := jwt.ValidationOptions{
    RequireExpiry:      true,
    RequireNotBefore:   true,
    ExpectedIssuer:     "auth.example.com",
    ExpectedAudience:   []string{"web-app", "mobile-app"},
    ClockSkew:          60 * time.Second,
}

claims, err := jwt.VerifyWithOptions(token, keyPair, opts)
```

### HMAC for Internal Services

```go
secret := []byte("your-secret-min-32-bytes")

// Sign
token, _ := jwt.SignWithSecret(claims, secret, "HS256", "key-id")

// Verify
claims, _ := jwt.VerifyWithSecret(token, secret)
```

## Related Documentation

- [JWT Module README](../../../jose/jwt/README.md)
- [JWS Examples](../jws/doc.md)
- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)
