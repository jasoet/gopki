# JOSE Testing Strategy

## Overview

Comprehensive testing strategy for JOSE implementation to ensure correctness, security, and interoperability.

**Target**: 85%+ test coverage across all JOSE modules

---

## Testing Layers

### 1. Unit Tests
**Purpose**: Test individual functions and components

**Coverage Target**: 90%+

**Test Files**:
- `jwt/jwt_test.go`
- `jws/jws_test.go`
- `jwe/jwe_test.go`
- `jwk/jwk_test.go`

### 2. Integration Tests
**Purpose**: Test component interactions

**Coverage Target**: 85%+

**Scenarios**:
- JWT ↔ JWK integration
- JWE ↔ JWK integration
- Multi-component workflows

### 3. Interoperability Tests
**Purpose**: Ensure compatibility with other libraries

**Libraries**:
- `golang-jwt/jwt/v5`
- `go-jose/go-jose/v4`
- Node.js `jsonwebtoken`
- Python `PyJWT`

### 4. RFC Compliance Tests
**Purpose**: Validate against RFC test vectors

**RFCs**:
- RFC 7515 (JWS)
- RFC 7516 (JWE)
- RFC 7517 (JWK)
- RFC 7518 (JWA)
- RFC 7519 (JWT)

### 5. Security Tests
**Purpose**: Prevent vulnerabilities

**Focus**:
- Algorithm confusion attacks
- Token forgery attempts
- Timing attacks
- Input validation

---

## Test Matrix

### JWT Tests

```go
// jwt/jwt_test.go

func TestJWTSignVerify(t *testing.T) {
    algorithms := []jwt.Algorithm{
        jwt.RS256, jwt.RS384, jwt.RS512,
        jwt.ES256, jwt.ES384, jwt.ES512,
        jwt.EdDSA,
        jwt.HS256, jwt.HS384, jwt.HS512,
    }

    for _, alg := range algorithms {
        t.Run(string(alg), func(t *testing.T) {
            // Test sign/verify round-trip
        })
    }
}

func TestClaimsValidation(t *testing.T) {
    tests := []struct {
        name string
        claims *jwt.Claims
        opts *jwt.ValidationOptions
        wantErr error
    }{
        {
            name: "Expired token",
            claims: &jwt.Claims{
                ExpiresAt: time.Now().Add(-time.Hour).Unix(),
            },
            opts: jwt.DefaultValidationOptions(),
            wantErr: jwt.ErrTokenExpired,
        },
        {
            name: "Token not yet valid",
            claims: &jwt.Claims{
                NotBefore: time.Now().Add(time.Hour).Unix(),
            },
            opts: jwt.DefaultValidationOptions(),
            wantErr: jwt.ErrTokenNotYetValid,
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.claims.Validate(tt.opts)
            if !errors.Is(err, tt.wantErr) {
                t.Errorf("got %v, want %v", err, tt.wantErr)
            }
        })
    }
}

func TestAlgorithmConfusion(t *testing.T) {
    // Create token with RS256
    token, _ := jwt.Sign(claims, rsaPrivateKey, jwt.RS256, nil)

    // Try to verify as HS256 (should fail)
    opts := &jwt.VerifyOptions{
        ExpectedAlgorithm: jwt.HS256,
    }

    _, err := jwt.VerifyWithSecret(token, []byte("secret"), opts)
    if err == nil {
        t.Error("Expected algorithm mismatch error")
    }
}

func TestNoneAlgorithm(t *testing.T) {
    // Try to create token with 'none' algorithm
    // Should be rejected
}
```

---

### JWK Tests

```go
// jwk/jwk_test.go

func TestJWKRoundTrip(t *testing.T) {
    keyTypes := []struct {
        name string
        keyPair interface{}
    }{
        {"RSA-2048", rsaKeyPair},
        {"ECDSA-P256", ecdsaP256KeyPair},
        {"ECDSA-P384", ecdsaP384KeyPair},
        {"Ed25519", ed25519KeyPair},
    }

    for _, tt := range keyTypes {
        t.Run(tt.name, func(t *testing.T) {
            // Export to JWK
            jwkData, err := jwk.FromGoPKIKeyPair(tt.keyPair, "sig", "test-key")
            require.NoError(t, err)

            // Marshal to JSON
            jsonData, err := json.Marshal(jwkData)
            require.NoError(t, err)

            // Parse back
            parsed, err := jwk.Parse(jsonData)
            require.NoError(t, err)

            // Convert to GoPKI
            imported, err := parsed.ToGoPKIKeyPair()
            require.NoError(t, err)

            // Keys should be equivalent
            // (test by signing and verifying)
        })
    }
}

func TestJWKSetOperations(t *testing.T) {
    jwks := &jwk.JWKSet{}

    // Add keys
    jwks.Add(jwk1)
    jwks.Add(jwk2)

    // Find by ID
    found, err := jwks.FindByKeyID("key-1")
    require.NoError(t, err)
    assert.Equal(t, "key-1", found.KeyID)

    // Remove key
    removed := jwks.Remove("key-1")
    assert.True(t, removed)

    // Should not find removed key
    _, err = jwks.FindByKeyID("key-1")
    assert.Error(t, err)
}

func TestJWKThumbprint(t *testing.T) {
    // Test against RFC 7638 examples
    jwkData := /* RFC example */

    thumbprint, err := jwkData.Thumbprint(crypto.SHA256)
    require.NoError(t, err)

    expected := /* RFC expected value */
    assert.Equal(t, expected, thumbprint)
}
```

---

### Interoperability Tests

```go
// compatibility/jose/compat_test.go

func TestGolangJWTInterop(t *testing.T) {
    // GoPKI creates, golang-jwt verifies
    gopkiToken, _ := jwt.Sign(claims, rsaKey, jwt.RS256, nil)

    golangClaims := golangJWT.MapClaims{}
    _, err := golangJWT.ParseWithClaims(
        gopkiToken,
        golangClaims,
        func(token *golangJWT.Token) (interface{}, error) {
            return rsaPublicKey, nil
        },
    )
    require.NoError(t, err)

    // golang-jwt creates, GoPKI verifies
    golangToken := golangJWT.NewWithClaims(
        golangJWT.SigningMethodRS256,
        golangJWT.MapClaims{"sub": "user123"},
    )
    golangTokenString, _ := golangToken.SignedString(rsaKey)

    gopkiClaims, err := jwt.Verify(golangTokenString, rsaPublicKey, nil)
    require.NoError(t, err)
    assert.Equal(t, "user123", gopkiClaims.Subject)
}

func TestGoJOSEInterop(t *testing.T) {
    // Similar tests with go-jose
}
```

---

### RFC Compliance Tests

```go
// jose/rfc_test.go

func TestRFC7515Examples(t *testing.T) {
    // Load RFC 7515 test vectors
    vectors := loadRFC7515Vectors()

    for _, v := range vectors {
        t.Run(v.Name, func(t *testing.T) {
            // Parse JWS
            token, err := jws.Parse(v.JWS)
            require.NoError(t, err)

            // Verify
            valid, err := jws.Verify(token, v.PublicKey)
            require.NoError(t, err)
            assert.True(t, valid)

            // Verify payload matches
            assert.Equal(t, v.ExpectedPayload, token.Payload)
        })
    }
}

func TestRFC7516Examples(t *testing.T) {
    // JWE test vectors
}

func TestRFC7517Examples(t *testing.T) {
    // JWK test vectors
}
```

---

### Security Tests

```go
// jose/security_test.go

func TestAlgorithmConfusionAttack(t *testing.T) {
    // Attack: Sign with HMAC, verify as RSA
    secret := []byte("secret-key")
    token, _ := jwt.SignWithSecret(claims, secret, jwt.HS256)

    // Attacker tries to use RSA public key as HMAC secret
    // This should FAIL
    _, err := jwt.Verify(token, rsaPublicKey, &jwt.VerifyOptions{
        ExpectedAlgorithm: jwt.RS256,
    })

    assert.Error(t, err)
}

func TestNoneAlgorithmRejection(t *testing.T) {
    // Create token with 'none' algorithm
    tokenWithNone := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0."

    // Should be rejected
    _, err := jwt.Verify(tokenWithNone, nil, nil)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "none")
}

func TestTokenForgeryPrevention(t *testing.T) {
    // Try to modify claims without re-signing
    validToken, _ := jwt.Sign(claims, rsaKey, jwt.RS256, nil)

    // Parse and modify
    parts := strings.Split(validToken, ".")
    modifiedClaims := /* tampered claims */
    forgedToken := parts[0] + "." + modifiedClaims + "." + parts[2]

    // Verification should fail
    _, err := jwt.Verify(forgedToken, rsaPublicKey, nil)
    assert.Error(t, err)
}

func TestTimingAttacks(t *testing.T) {
    // Test constant-time HMAC comparison
    validMAC := /* ... */
    invalidMAC := /* ... */

    // Measure time for valid vs invalid
    // Should be similar (constant time)

    validDuration := measureVerifyTime(validMAC)
    invalidDuration := measureVerifyTime(invalidMAC)

    // Allow some variance but should be close
    ratio := float64(validDuration) / float64(invalidDuration)
    assert.InDelta(t, 1.0, ratio, 0.1)
}

func TestExpiryBoundaries(t *testing.T) {
    // Test clock skew handling
    // Test exactly at expiry time
    // Test with negative clock skew
}

func TestInputValidation(t *testing.T) {
    // Nil inputs
    // Empty strings
    // Malformed Base64
    // Invalid JSON
    // Oversized tokens
}
```

---

### Performance Benchmarks

```go
// jose/benchmark_test.go

func BenchmarkJWTSign(b *testing.B) {
    algorithms := []jwt.Algorithm{
        jwt.RS256, jwt.ES256, jwt.EdDSA, jwt.HS256,
    }

    for _, alg := range algorithms {
        b.Run(string(alg), func(b *testing.B) {
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                jwt.Sign(claims, key, alg, nil)
            }
        })
    }
}

func BenchmarkJWTVerify(b *testing.B) {
    // Similar for verification
}

func BenchmarkJWKExport(b *testing.B) {
    for i := 0; i < b.N; i++ {
        jwk.FromGoPKIKeyPair(keyPair, "sig", "test")
    }
}

func BenchmarkJWKImport(b *testing.B) {
    for i := 0; i < b.N; i++ {
        jwkData.ToGoPKIKeyPair()
    }
}
```

---

## Test Coverage Targets

| Module | Target | Focus Areas |
|--------|--------|-------------|
| `jwt/` | 90%+ | All algorithms, claims validation, errors |
| `jws/` | 85%+ | Compact & JSON formats, multi-sig |
| `jwe/` | 85%+ | Encryption modes, key wrapping |
| `jwk/` | 90%+ | Import/export, JWKS operations |
| Overall | 85%+ | Integration and edge cases |

---

## Testing Checklist

### Phase 1: Unit Tests
- [ ] JWT sign/verify (all algorithms)
- [ ] Claims validation (all scenarios)
- [ ] JWK import/export (all key types)
- [ ] JWS compact format
- [ ] JWE compact format

### Phase 2: Integration Tests
- [ ] JWT + JWK integration
- [ ] Multi-signature JWS
- [ ] Multi-recipient JWE
- [ ] JWKS operations

### Phase 3: Interoperability
- [ ] golang-jwt/jwt compatibility
- [ ] go-jose compatibility
- [ ] Cross-language tests (optional)

### Phase 4: RFC Compliance
- [ ] RFC 7515 test vectors (JWS)
- [ ] RFC 7516 test vectors (JWE)
- [ ] RFC 7517 test vectors (JWK)
- [ ] RFC 7519 test vectors (JWT)

### Phase 5: Security
- [ ] Algorithm confusion prevention
- [ ] 'none' algorithm rejection
- [ ] Token forgery prevention
- [ ] Timing attack resistance
- [ ] Input validation

### Phase 6: Performance
- [ ] Sign/verify benchmarks
- [ ] Import/export benchmarks
- [ ] Memory usage profiling
- [ ] Comparison with other libraries

---

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: JOSE Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.24'

      - name: Run Unit Tests
        run: go test -v -race -coverprofile=coverage.out ./jose/...

      - name: Run Interop Tests
        run: go test -v -tags=interop ./compatibility/jose/...

      - name: Run Security Tests
        run: go test -v -tags=security ./jose/...

      - name: Check Coverage
        run: |
          go tool cover -func=coverage.out
          # Fail if coverage < 85%

      - name: Upload Coverage
        uses: codecov/codecov-action@v3
```

---

## Test Data Management

### Test Fixtures

```go
// testdata/jwt_fixtures.json
{
  "rsa_tokens": [
    {
      "algorithm": "RS256",
      "token": "...",
      "public_key": "...",
      "expected_claims": {...}
    }
  ],
  "ecdsa_tokens": [...],
  "ed25519_tokens": [...]
}
```

### Loading Test Data

```go
func loadFixtures(t *testing.T) *Fixtures {
    data, err := os.ReadFile("testdata/jwt_fixtures.json")
    require.NoError(t, err)

    var fixtures Fixtures
    err = json.Unmarshal(data, &fixtures)
    require.NoError(t, err)

    return &fixtures
}
```

---

## Conclusion

Comprehensive testing ensures JOSE implementation is:
- ✅ Correct (RFC compliant)
- ✅ Secure (attack resistant)
- ✅ Compatible (interoperable)
- ✅ Performant (benchmarked)

**Total Test Code**: ~2,000 lines for 85%+ coverage

**Next**: [08_SECURITY.md](08_SECURITY.md) for security considerations.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
