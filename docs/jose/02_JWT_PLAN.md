# JWT Implementation Plan

## Overview

This document provides the detailed implementation plan for JWT (JSON Web Token) support in GoPKI, leveraging existing cryptographic infrastructure to minimize new code while maintaining type safety and security.

**RFC**: [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

---

## What is JWT?

**JWT** (JSON Web Token) is a compact, URL-safe means of representing claims to be transferred between two parties.

### Structure

```
header.payload.signature
```

Each part is Base64URL encoded:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Decoded**:
```json
// Header
{
  "alg": "RS256",
  "typ": "JWT"
}

// Payload (Claims)
{
  "sub": "1234567890",
  "name": "John Doe",
  "exp": 1516239022
}

// Signature (validates authenticity)
```

---

## Implementation Strategy

### Core Principle: Leverage Existing Infrastructure

JWT is essentially **JWS with specific claims structure**. GoPKI already has:
- ✅ Signing algorithms (`signing/` - 77.4% coverage)
- ✅ Type-safe key management (`keypair/` - 75.3% coverage)
- ✅ Hash algorithms (SHA-256/384/512)

**We only need to add**:
1. JWT token structure (~40 lines)
2. Claims handling (~40 lines)
3. Base64URL encoding (~30 lines)
4. Claims validation (~40 lines)
5. HMAC support (~20 lines)
6. Integration glue (~20 lines)

**Total: ~190 lines of new code**

---

## Module Structure

```
jose/jwt/
├── jwt.go           # Main JWT operations (Sign, Verify, Parse)
├── token.go         # Token structure and encoding
├── claims.go        # Claims definition and marshaling
├── validation.go    # Claims validation logic
├── algorithms.go    # Algorithm mapping to GoPKI
├── encoding.go      # Base64URL utilities
├── hmac.go          # HMAC support (HS256/384/512)
├── errors.go        # JWT-specific errors
├── options.go       # Sign/Verify options
│
├── jwt_test.go      # Core JWT tests
├── claims_test.go   # Claims validation tests
├── hmac_test.go     # HMAC algorithm tests
└── compat_test.go   # Interop with golang-jwt
```

---

## Detailed Implementation

### 1. Token Structure (`token.go`)

```go
package jwt

import (
    "strings"
)

// Token represents a parsed JWT
type Token struct {
    // Header contains JWT header (alg, typ, kid)
    Header Header

    // Claims contains the JWT claims
    Claims *Claims

    // Raw components
    RawHeader    string // Base64URL encoded header
    RawClaims    string // Base64URL encoded claims
    RawSignature string // Base64URL encoded signature

    // Signature bytes (decoded)
    Signature []byte
}

// Header represents JWT header
type Header struct {
    Algorithm Algorithm `json:"alg"`           // Signing algorithm
    Type      string    `json:"typ,omitempty"` // Token type (usually "JWT")
    KeyID     string    `json:"kid,omitempty"` // Key ID
}

// String returns compact JWT representation
func (t *Token) String() string {
    return t.RawHeader + "." + t.RawClaims + "." + t.RawSignature
}

// SigningInput returns the data to be signed (header.claims)
func (t *Token) SigningInput() string {
    return t.RawHeader + "." + t.RawClaims
}

// Parse parses a JWT string without verification
func Parse(tokenString string) (*Token, error) {
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        return nil, ErrInvalidTokenFormat
    }

    // Decode header
    headerBytes, err := base64URLDecode(parts[0])
    if err != nil {
        return nil, fmt.Errorf("invalid header encoding: %w", err)
    }

    var header Header
    if err := json.Unmarshal(headerBytes, &header); err != nil {
        return nil, fmt.Errorf("invalid header JSON: %w", err)
    }

    // Decode claims
    claimsBytes, err := base64URLDecode(parts[1])
    if err != nil {
        return nil, fmt.Errorf("invalid claims encoding: %w", err)
    }

    var claims Claims
    if err := json.Unmarshal(claimsBytes, &claims); err != nil {
        return nil, fmt.Errorf("invalid claims JSON: %w", err)
    }

    // Decode signature
    signature, err := base64URLDecode(parts[2])
    if err != nil {
        return nil, fmt.Errorf("invalid signature encoding: %w", err)
    }

    return &Token{
        Header:       header,
        Claims:       &claims,
        RawHeader:    parts[0],
        RawClaims:    parts[1],
        RawSignature: parts[2],
        Signature:    signature,
    }, nil
}
```

**Lines**: ~80

---

### 2. Claims Structure (`claims.go`)

```go
package jwt

import (
    "encoding/json"
    "time"
)

// Claims represents JWT claims (RFC 7519 Section 4)
type Claims struct {
    // Registered claims (RFC 7519 Section 4.1)
    Issuer    string   `json:"iss,omitempty"` // Issuer
    Subject   string   `json:"sub,omitempty"` // Subject
    Audience  Audience `json:"aud,omitempty"` // Audience (string or []string)
    ExpiresAt int64    `json:"exp,omitempty"` // Expiration time (Unix timestamp)
    NotBefore int64    `json:"nbf,omitempty"` // Not before (Unix timestamp)
    IssuedAt  int64    `json:"iat,omitempty"` // Issued at (Unix timestamp)
    JWTID     string   `json:"jti,omitempty"` // JWT ID

    // Custom claims (private/public)
    Extra map[string]interface{} `json:"-"`
}

// Audience can be a single string or array of strings
type Audience []string

// UnmarshalJSON handles both string and []string for audience
func (a *Audience) UnmarshalJSON(data []byte) error {
    var single string
    if err := json.Unmarshal(data, &single); err == nil {
        *a = Audience{single}
        return nil
    }

    var multiple []string
    if err := json.Unmarshal(data, &multiple); err != nil {
        return err
    }
    *a = Audience(multiple)
    return nil
}

// MarshalJSON returns single string if len==1, else array
func (a Audience) MarshalJSON() ([]byte, error) {
    if len(a) == 1 {
        return json.Marshal(a[0])
    }
    return json.Marshal([]string(a))
}

// MarshalJSON custom marshaling to include Extra claims
func (c *Claims) MarshalJSON() ([]byte, error) {
    type Alias Claims
    aux := &struct {
        *Alias
    }{
        Alias: (*Alias)(c),
    }

    data, err := json.Marshal(aux)
    if err != nil {
        return nil, err
    }

    if len(c.Extra) == 0 {
        return data, nil
    }

    // Merge Extra claims
    var m map[string]interface{}
    json.Unmarshal(data, &m)

    for k, v := range c.Extra {
        m[k] = v
    }

    return json.Marshal(m)
}

// UnmarshalJSON custom unmarshaling to extract Extra claims
func (c *Claims) UnmarshalJSON(data []byte) error {
    type Alias Claims
    aux := &struct {
        *Alias
    }{
        Alias: (*Alias)(c),
    }

    if err := json.Unmarshal(data, aux); err != nil {
        return err
    }

    // Extract extra claims
    var all map[string]interface{}
    json.Unmarshal(data, &all)

    // Remove registered claims
    registered := map[string]bool{
        "iss": true, "sub": true, "aud": true,
        "exp": true, "nbf": true, "iat": true, "jti": true,
    }

    c.Extra = make(map[string]interface{})
    for k, v := range all {
        if !registered[k] {
            c.Extra[k] = v
        }
    }

    return nil
}

// NewClaims creates claims with current timestamp
func NewClaims() *Claims {
    now := time.Now().Unix()
    return &Claims{
        IssuedAt: now,
        Extra:    make(map[string]interface{}),
    }
}

// SetExpiration sets expiration time from duration
func (c *Claims) SetExpiration(d time.Duration) {
    c.ExpiresAt = time.Now().Add(d).Unix()
}

// SetNotBefore sets not-before time from duration
func (c *Claims) SetNotBefore(d time.Duration) {
    c.NotBefore = time.Now().Add(d).Unix()
}
```

**Lines**: ~120

---

### 3. Claims Validation (`validation.go`)

```go
package jwt

import (
    "errors"
    "fmt"
    "time"
)

// ValidationOptions configures claims validation
type ValidationOptions struct {
    // Validate expiration time
    ValidateExpiry bool

    // Validate not-before time
    ValidateNotBefore bool

    // Validate issuer
    ValidateIssuer bool
    ExpectedIssuer string

    // Validate audience
    ValidateAudience bool
    ExpectedAudience []string

    // Clock skew tolerance (default: 60s)
    ClockSkew time.Duration

    // Current time (for testing)
    Now func() time.Time
}

// DefaultValidationOptions returns default options
func DefaultValidationOptions() *ValidationOptions {
    return &ValidationOptions{
        ValidateExpiry:    true,
        ValidateNotBefore: true,
        ClockSkew:         60 * time.Second,
        Now:               time.Now,
    }
}

// Validate validates claims according to options
func (c *Claims) Validate(opts *ValidationOptions) error {
    if opts == nil {
        opts = DefaultValidationOptions()
    }

    now := opts.Now().Unix()
    skew := int64(opts.ClockSkew.Seconds())

    // Validate expiration
    if opts.ValidateExpiry && c.ExpiresAt != 0 {
        if now > c.ExpiresAt+skew {
            return ErrTokenExpired
        }
    }

    // Validate not-before
    if opts.ValidateNotBefore && c.NotBefore != 0 {
        if now < c.NotBefore-skew {
            return ErrTokenNotYetValid
        }
    }

    // Validate issuer
    if opts.ValidateIssuer {
        if c.Issuer != opts.ExpectedIssuer {
            return fmt.Errorf("%w: got %q, want %q",
                ErrInvalidIssuer, c.Issuer, opts.ExpectedIssuer)
        }
    }

    // Validate audience
    if opts.ValidateAudience {
        if !c.hasAudience(opts.ExpectedAudience) {
            return fmt.Errorf("%w: %v", ErrInvalidAudience, c.Audience)
        }
    }

    return nil
}

// hasAudience checks if any expected audience is in claims
func (c *Claims) hasAudience(expected []string) bool {
    if len(expected) == 0 {
        return len(c.Audience) > 0
    }

    for _, exp := range expected {
        for _, aud := range c.Audience {
            if aud == exp {
                return true
            }
        }
    }
    return false
}
```

**Lines**: ~80

---

### 4. Algorithm Mapping (`algorithms.go`)

```go
package jwt

import (
    "crypto"
    "fmt"

    "github.com/jasoet/gopki/signing"
)

// Algorithm represents JWT signing algorithm
type Algorithm string

const (
    // RSA algorithms
    RS256 Algorithm = "RS256" // RSA + SHA-256
    RS384 Algorithm = "RS384" // RSA + SHA-384
    RS512 Algorithm = "RS512" // RSA + SHA-512

    // RSA-PSS algorithms
    PS256 Algorithm = "PS256" // RSA-PSS + SHA-256
    PS384 Algorithm = "PS384" // RSA-PSS + SHA-384
    PS512 Algorithm = "PS512" // RSA-PSS + SHA-512

    // ECDSA algorithms
    ES256 Algorithm = "ES256" // ECDSA P-256 + SHA-256
    ES384 Algorithm = "ES384" // ECDSA P-384 + SHA-384
    ES512 Algorithm = "ES512" // ECDSA P-521 + SHA-512

    // Ed25519 algorithm
    EdDSA Algorithm = "EdDSA" // Ed25519

    // HMAC algorithms
    HS256 Algorithm = "HS256" // HMAC + SHA-256
    HS384 Algorithm = "HS384" // HMAC + SHA-384
    HS512 Algorithm = "HS512" // HMAC + SHA-512
)

// toSignOptions converts JWT algorithm to GoPKI SignOptions
func (a Algorithm) toSignOptions() (*signing.SignOptions, error) {
    switch a {
    case RS256, PS256, ES256, HS256:
        return &signing.SignOptions{
            HashAlgorithm: crypto.SHA256,
        }, nil

    case RS384, PS384, ES384, HS384:
        return &signing.SignOptions{
            HashAlgorithm: crypto.SHA384,
        }, nil

    case RS512, PS512, ES512, HS512:
        return &signing.SignOptions{
            HashAlgorithm: crypto.SHA512,
        }, nil

    case EdDSA:
        return &signing.SignOptions{}, nil

    default:
        return nil, fmt.Errorf("unsupported algorithm: %s", a)
    }
}

// HashFunc returns hash function for algorithm
func (a Algorithm) HashFunc() (crypto.Hash, error) {
    switch a {
    case RS256, PS256, ES256, HS256:
        return crypto.SHA256, nil
    case RS384, PS384, ES384, HS384:
        return crypto.SHA384, nil
    case RS512, PS512, ES512, HS512:
        return crypto.SHA512, nil
    case EdDSA:
        return 0, nil // Ed25519 doesn't use hash
    default:
        return 0, fmt.Errorf("unsupported algorithm: %s", a)
    }
}

// IsHMAC returns true if algorithm is HMAC-based
func (a Algorithm) IsHMAC() bool {
    return a == HS256 || a == HS384 || a == HS512
}
```

**Lines**: ~70

---

### 5. Base64URL Encoding (`encoding.go`)

```go
package jwt

import (
    "encoding/base64"
    "encoding/json"
)

var base64URLEncoding = base64.RawURLEncoding

// base64URLEncode encodes data using Base64URL (no padding)
func base64URLEncode(data []byte) string {
    return base64URLEncoding.EncodeToString(data)
}

// base64URLDecode decodes Base64URL encoded data
func base64URLDecode(s string) ([]byte, error) {
    return base64URLEncoding.DecodeString(s)
}

// encodeSegment JSON marshals and Base64URL encodes
func encodeSegment(v interface{}) (string, error) {
    data, err := json.Marshal(v)
    if err != nil {
        return "", err
    }
    return base64URLEncode(data), nil
}

// decodeSegment Base64URL decodes and JSON unmarshals
func decodeSegment(s string, v interface{}) error {
    data, err := base64URLDecode(s)
    if err != nil {
        return err
    }
    return json.Unmarshal(data, v)
}
```

**Lines**: ~30

---

### 6. Main JWT Operations (`jwt.go`)

```go
package jwt

import (
    "fmt"

    "github.com/jasoet/gopki/keypair"
    "github.com/jasoet/gopki/signing"
)

// Sign creates and signs a JWT using asymmetric key
func Sign[K keypair.PrivateKey](claims *Claims, key K, alg Algorithm, opts *SignOptions) (string, error) {
    if alg.IsHMAC() {
        return "", fmt.Errorf("use SignWithSecret for HMAC algorithms")
    }

    // Create header
    header := Header{
        Algorithm: alg,
        Type:      "JWT",
        KeyID:     opts.KeyID,
    }

    // Encode header and claims
    headerStr, err := encodeSegment(header)
    if err != nil {
        return "", fmt.Errorf("encode header: %w", err)
    }

    claimsStr, err := encodeSegment(claims)
    if err != nil {
        return "", fmt.Errorf("encode claims: %w", err)
    }

    // Create signing input
    signingInput := headerStr + "." + claimsStr

    // Get signing options
    signOpts, err := alg.toSignOptions()
    if err != nil {
        return "", err
    }

    // Sign using GoPKI signing module
    signature, err := signWithKey([]byte(signingInput), key, signOpts)
    if err != nil {
        return "", fmt.Errorf("sign: %w", err)
    }

    // Encode signature
    sigStr := base64URLEncode(signature)

    return signingInput + "." + sigStr, nil
}

// Verify verifies JWT signature and validates claims
func Verify[K keypair.PublicKey](tokenString string, key K, opts *VerifyOptions) (*Claims, error) {
    // Parse token
    token, err := Parse(tokenString)
    if err != nil {
        return nil, err
    }

    // Check algorithm
    if opts.ExpectedAlgorithm != "" && token.Header.Algorithm != opts.ExpectedAlgorithm {
        return nil, fmt.Errorf("%w: got %s, want %s",
            ErrAlgorithmMismatch, token.Header.Algorithm, opts.ExpectedAlgorithm)
    }

    // Verify signature using GoPKI
    signingInput := []byte(token.SigningInput())
    valid, err := verifyWithKey(signingInput, token.Signature, key, token.Header.Algorithm)
    if err != nil {
        return nil, fmt.Errorf("verify signature: %w", err)
    }

    if !valid {
        return nil, ErrInvalidSignature
    }

    // Validate claims
    if err := token.Claims.Validate(opts.Validation); err != nil {
        return nil, err
    }

    return token.Claims, nil
}

// SignWithSecret signs JWT using HMAC (symmetric key)
func SignWithSecret(claims *Claims, secret []byte, alg Algorithm) (string, error) {
    if !alg.IsHMAC() {
        return "", fmt.Errorf("use Sign for asymmetric algorithms")
    }

    // Create header
    header := Header{
        Algorithm: alg,
        Type:      "JWT",
    }

    // Encode header and claims
    headerStr, err := encodeSegment(header)
    if err != nil {
        return "", err
    }

    claimsStr, err := encodeSegment(claims)
    if err != nil {
        return "", err
    }

    // Create signing input
    signingInput := headerStr + "." + claimsStr

    // Sign with HMAC
    hash, _ := alg.HashFunc()
    signature, err := signHMAC([]byte(signingInput), secret, hash)
    if err != nil {
        return "", err
    }

    sigStr := base64URLEncode(signature)
    return signingInput + "." + sigStr, nil
}

// VerifyWithSecret verifies HMAC-signed JWT
func VerifyWithSecret(tokenString string, secret []byte, opts *VerifyOptions) (*Claims, error) {
    token, err := Parse(tokenString)
    if err != nil {
        return nil, err
    }

    if !token.Header.Algorithm.IsHMAC() {
        return nil, fmt.Errorf("token not HMAC-signed")
    }

    // Verify HMAC
    hash, _ := token.Header.Algorithm.HashFunc()
    valid := verifyHMAC([]byte(token.SigningInput()), token.Signature, secret, hash)
    if !valid {
        return nil, ErrInvalidSignature
    }

    // Validate claims
    if err := token.Claims.Validate(opts.Validation); err != nil {
        return nil, err
    }

    return token.Claims, nil
}
```

**Lines**: ~120

---

### 7. HMAC Support (`hmac.go`)

```go
package jwt

import (
    "crypto"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "fmt"
    "hash"
)

// signHMAC creates HMAC signature
func signHMAC(data []byte, secret []byte, hashAlg crypto.Hash) ([]byte, error) {
    var h func() hash.Hash

    switch hashAlg {
    case crypto.SHA256:
        h = sha256.New
    case crypto.SHA384:
        h = sha512.New384
    case crypto.SHA512:
        h = sha512.New
    default:
        return nil, fmt.Errorf("unsupported hash: %v", hashAlg)
    }

    mac := hmac.New(h, secret)
    mac.Write(data)
    return mac.Sum(nil), nil
}

// verifyHMAC verifies HMAC signature (constant time)
func verifyHMAC(data, signature, secret []byte, hashAlg crypto.Hash) bool {
    expectedMAC, err := signHMAC(data, secret, hashAlg)
    if err != nil {
        return false
    }
    return hmac.Equal(signature, expectedMAC)
}
```

**Lines**: ~35

---

### 8. Sign/Verify Options (`options.go`)

```go
package jwt

import "time"

// SignOptions configures JWT signing
type SignOptions struct {
    // Key ID to include in header
    KeyID string

    // Auto-set expiration
    ExpiresIn time.Duration

    // Auto-set not-before
    NotBefore time.Time
}

// VerifyOptions configures JWT verification
type VerifyOptions struct {
    // Expected algorithm (reject if mismatch)
    ExpectedAlgorithm Algorithm

    // Claims validation options
    Validation *ValidationOptions
}

// DefaultSignOptions returns default sign options
func DefaultSignOptions() *SignOptions {
    return &SignOptions{}
}

// DefaultVerifyOptions returns default verify options
func DefaultVerifyOptions() *VerifyOptions {
    return &VerifyOptions{
        Validation: DefaultValidationOptions(),
    }
}
```

**Lines**: ~30

---

### 9. Errors (`errors.go`)

```go
package jwt

import "errors"

var (
    ErrInvalidTokenFormat = errors.New("invalid JWT format")
    ErrInvalidSignature   = errors.New("invalid signature")
    ErrTokenExpired       = errors.New("token expired")
    ErrTokenNotYetValid   = errors.New("token not yet valid")
    ErrInvalidIssuer      = errors.New("invalid issuer")
    ErrInvalidAudience    = errors.New("invalid audience")
    ErrAlgorithmMismatch  = errors.New("algorithm mismatch")
    ErrAlgorithmNone      = errors.New("'none' algorithm not allowed")
)
```

**Lines**: ~15

---

## Testing Strategy

### Unit Tests (`jwt_test.go`)

```go
func TestJWTRoundTrip(t *testing.T) {
    tests := []struct {
        name string
        alg  Algorithm
        key  interface{}
    }{
        {"RS256", RS256, rsaKeyPair},
        {"ES256", ES256, ecdsaKeyPair},
        {"EdDSA", EdDSA, ed25519KeyPair},
        {"HS256", HS256, []byte("secret")},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            claims := NewClaims()
            claims.Subject = "user123"
            claims.SetExpiration(time.Hour)

            // Sign
            var token string
            var err error

            if tt.alg.IsHMAC() {
                token, err = SignWithSecret(claims, tt.key.([]byte), tt.alg)
            } else {
                token, err = Sign(claims, tt.key, tt.alg, DefaultSignOptions())
            }

            require.NoError(t, err)

            // Verify
            var verified *Claims
            if tt.alg.IsHMAC() {
                verified, err = VerifyWithSecret(token, tt.key.([]byte), DefaultVerifyOptions())
            } else {
                verified, err = Verify(token, publicKey(tt.key), DefaultVerifyOptions())
            }

            require.NoError(t, err)
            assert.Equal(t, claims.Subject, verified.Subject)
        })
    }
}

func TestClaimsValidation(t *testing.T) {
    // Test expiry, not-before, issuer, audience
}

func TestAlgorithmConfusion(t *testing.T) {
    // Test algorithm confusion attack prevention
}

func TestNoneAlgorithm(t *testing.T) {
    // Test 'none' algorithm rejection
}
```

### Compatibility Tests (`compat_test.go`)

```go
func TestGolangJWTCompatibility(t *testing.T) {
    // Create token with GoPKI
    gopkiToken, _ := jwt.Sign(claims, rsaKey, jwt.RS256, nil)

    // Verify with golang-jwt/jwt
    golangJWTClaims, err := golangJWT.Parse(gopkiToken, ...)
    require.NoError(t, err)

    // Create token with golang-jwt
    golangToken, _ := golangJWT.Sign(...)

    // Verify with GoPKI
    gopkiClaims, err := jwt.Verify(golangToken, publicKey, nil)
    require.NoError(t, err)
}
```

---

## Integration with GoPKI

### Using Existing Signing Module

```go
// In jwt.go

func signWithKey[K keypair.PrivateKey](data []byte, key K, opts *signing.SignOptions) ([]byte, error) {
    // Use GoPKI's existing signing - already tested!
    switch k := any(key).(type) {
    case *rsa.PrivateKey:
        return signRSA(data, k, opts.HashAlgorithm)
    case *ecdsa.PrivateKey:
        return signECDSA(data, k, opts.HashAlgorithm)
    case ed25519.PrivateKey:
        return ed25519.Sign(k, data), nil
    default:
        return nil, fmt.Errorf("unsupported key type")
    }
}

func verifyWithKey[K keypair.PublicKey](data, sig []byte, key K, alg Algorithm) (bool, error) {
    // Use GoPKI's existing verification
    switch k := any(key).(type) {
    case *rsa.PublicKey:
        hash, _ := alg.HashFunc()
        return verifyRSA(data, sig, k, hash), nil
    case *ecdsa.PublicKey:
        return verifyECDSA(data, sig, k), nil
    case ed25519.PublicKey:
        return ed25519.Verify(k, data, sig), nil
    default:
        return false, fmt.Errorf("unsupported key type")
    }
}
```

---

## Usage Examples

### Basic JWT Signing

```go
import "github.com/jasoet/gopki/jose/jwt"

// Create claims
claims := jwt.NewClaims()
claims.Subject = "user123"
claims.Issuer = "https://auth.example.com"
claims.SetExpiration(24 * time.Hour)

// Sign with RSA
token, err := jwt.Sign(claims, rsaPrivateKey, jwt.RS256, jwt.DefaultSignOptions())

// Verify
opts := jwt.DefaultVerifyOptions()
opts.Validation.ExpectedIssuer = "https://auth.example.com"

verified, err := jwt.Verify(token, rsaPublicKey, opts)
```

### HMAC Signing

```go
secret := []byte("my-secret-key")

// Sign
token, err := jwt.SignWithSecret(claims, secret, jwt.HS256)

// Verify
verified, err := jwt.VerifyWithSecret(token, secret, jwt.DefaultVerifyOptions())
```

### Custom Claims

```go
claims := jwt.NewClaims()
claims.Subject = "user123"
claims.Extra["role"] = "admin"
claims.Extra["permissions"] = []string{"read", "write"}

token, _ := jwt.Sign(claims, key, jwt.ES256, nil)

// After verification
verified, _ := jwt.Verify(token, publicKey, nil)
role := verified.Extra["role"].(string)
```

---

## Security Considerations

### Algorithm Validation

```go
// ALWAYS specify expected algorithm
opts := &jwt.VerifyOptions{
    ExpectedAlgorithm: jwt.RS256, // Reject if mismatch
}
```

### Reject 'none' Algorithm

```go
// In algorithms.go
const (
    // 'none' algorithm is explicitly NOT defined
    // Parser will reject it
)

func (a Algorithm) toSignOptions() (*signing.SignOptions, error) {
    if a == "none" || a == "" {
        return nil, ErrAlgorithmNone
    }
    // ...
}
```

### Constant-Time Comparison

```go
// HMAC uses crypto/hmac.Equal (constant time)
func verifyHMAC(...) bool {
    return hmac.Equal(signature, expectedMAC) // ✅ Constant time
}
```

---

## Performance Targets

| Operation | Target | Algorithm |
|-----------|--------|-----------|
| Sign (RSA-2048) | < 1ms | RS256 |
| Verify (RSA-2048) | < 1ms | RS256 |
| Sign (ECDSA-P256) | < 0.5ms | ES256 |
| Verify (ECDSA-P256) | < 1ms | ES256 |
| Sign (Ed25519) | < 0.1ms | EdDSA |
| Verify (Ed25519) | < 0.2ms | EdDSA |
| Sign (HMAC) | < 0.05ms | HS256 |
| Verify (HMAC) | < 0.05ms | HS256 |
| Parse | < 0.01ms | All |

---

## Checklist

### Implementation
- [ ] Token structure and parsing
- [ ] Claims definition and marshaling
- [ ] Base64URL encoding
- [ ] Algorithm mapping to GoPKI
- [ ] Asymmetric signing (RS/ES/PS/EdDSA)
- [ ] HMAC signing (HS256/384/512)
- [ ] Claims validation
- [ ] Error handling

### Testing
- [ ] Unit tests (85%+ coverage)
- [ ] Claims validation tests
- [ ] Algorithm tests (all variants)
- [ ] Security tests (algorithm confusion, etc.)
- [ ] Compatibility tests (golang-jwt)
- [ ] RFC 7519 test vectors

### Documentation
- [ ] API documentation
- [ ] Usage examples
- [ ] Security best practices
- [ ] Migration guide from other libraries

---

## Next Steps

1. **Implement Base64URL encoding** (`encoding.go`)
2. **Implement token structure** (`token.go`)
3. **Implement claims** (`claims.go`)
4. **Add algorithm mapping** (`algorithms.go`)
5. **Add HMAC support** (`hmac.go`)
6. **Implement main operations** (`jwt.go`)
7. **Add validation** (`validation.go`)
8. **Write comprehensive tests**
9. **Add compatibility tests**
10. **Document and create examples**

**Estimated Time**: 1-2 weeks

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
**Status**: Planning Phase
