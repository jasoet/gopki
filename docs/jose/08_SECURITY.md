# JOSE Security Considerations

## Overview

Security guidelines and threat mitigation for JOSE implementation.

---

## Threat Model

### Assets to Protect
1. **Private keys** - Must remain confidential
2. **Signed data integrity** - Cannot be tampered
3. **Encrypted data confidentiality** - Only intended recipients
4. **Token authenticity** - Cannot be forged

### Threat Actors
1. **External attackers** - Malicious third parties
2. **Compromised clients** - Stolen credentials
3. **Man-in-the-middle** - Network attackers
4. **Insider threats** - Malicious users

---

## Common Vulnerabilities & Mitigations

### 1. Algorithm Confusion Attack

**Threat**: Attacker changes algorithm in header

**Example**:
```json
// Original (RSA signed)
{"alg": "RS256", "typ": "JWT"}

// Attacker changes to HMAC
{"alg": "HS256", "typ": "JWT"}
// Then uses RSA public key as HMAC secret
```

**Mitigation**:
```go
// ALWAYS specify expected algorithm
opts := &jwt.VerifyOptions{
    ExpectedAlgorithm: jwt.RS256, // Enforce specific algorithm
}

verified, err := jwt.Verify(token, key, opts)
if err != nil {
    // Reject if algorithm doesn't match
}
```

**Implementation**:
```go
// In jwt/jwt.go
func Verify[K keypair.PublicKey](token string, key K, opts *VerifyOptions) (*Claims, error) {
    parsed, _ := Parse(token)

    // Check algorithm BEFORE verifying
    if opts.ExpectedAlgorithm != "" && parsed.Header.Algorithm != opts.ExpectedAlgorithm {
        return nil, ErrAlgorithmMismatch
    }

    // Now verify...
}
```

---

### 2. 'none' Algorithm Attack

**Threat**: Token with no signature

**Example**:
```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
// No signature! Header says alg=none
```

**Mitigation**:
```go
// REJECT 'none' algorithm ALWAYS
const (
    // Explicitly DO NOT define 'none' as valid algorithm
)

func (a Algorithm) toSignOptions() (*signing.SignOptions, error) {
    if a == "none" || a == "" {
        return nil, ErrAlgorithmNone
    }
    // ...
}
```

**Implementation**:
```go
// In jwt/algorithms.go
var ErrAlgorithmNone = errors.New("'none' algorithm not allowed")

// Validation
func validateAlgorithm(alg Algorithm) error {
    if string(alg) == "none" || string(alg) == "" {
        return ErrAlgorithmNone
    }

    validAlgorithms := map[Algorithm]bool{
        RS256: true, RS384: true, RS512: true,
        ES256: true, ES384: true, ES512: true,
        EdDSA: true,
        HS256: true, HS384: true, HS512: true,
    }

    if !validAlgorithms[alg] {
        return fmt.Errorf("unsupported algorithm: %s", alg)
    }

    return nil
}
```

---

### 3. Token Replay Attacks

**Threat**: Reuse valid tokens after logout/revocation

**Mitigation 1: Short Expiration**
```go
claims := jwt.NewClaims()
claims.SetExpiration(15 * time.Minute) // Short-lived
```

**Mitigation 2: JTI (JWT ID) + Blocklist**
```go
claims.JWTID = uuid.New().String() // Unique ID

// Store revoked JTIs in Redis/DB
func isRevoked(jti string) bool {
    return redis.Exists("revoked:"+jti)
}

// Before accepting token
if isRevoked(claims.JWTID) {
    return ErrTokenRevoked
}
```

**Mitigation 3: Refresh Token Pattern**
```
Access Token: 15 min expiry (stateless JWT)
Refresh Token: 30 days (stored in DB, revocable)
```

---

### 4. Timing Attacks on HMAC

**Threat**: Infer secret through timing differences

**Vulnerable Code**:
```go
// DON'T DO THIS
if bytes.Equal(signature, expectedSignature) { // Timing leak!
    return true
}
```

**Secure Code**:
```go
// Always use constant-time comparison
if hmac.Equal(signature, expectedSignature) { // ✅ Constant time
    return true
}
```

**Implementation**:
```go
// In jwt/hmac.go
func verifyHMAC(data, signature, secret []byte, hash crypto.Hash) bool {
    expectedMAC, err := signHMAC(data, secret, hash)
    if err != nil {
        return false
    }

    // MUST use constant-time comparison
    return hmac.Equal(signature, expectedMAC)
}
```

---

### 5. Key Confusion Attacks

**Threat**: Use wrong key type for algorithm

**Example**:
```go
// Token signed with RSA private key
token, _ := jwt.Sign(claims, rsaPrivKey, jwt.RS256, nil)

// Attacker tries to verify with ECDSA public key (wrong type)
verified, _ := jwt.Verify(token, ecdsaPubKey, nil) // Should fail!
```

**Mitigation**:
```go
// Type-safe verification (GoPKI advantage!)
func Verify[K keypair.PublicKey](token string, key K, opts *VerifyOptions) (*Claims, error) {
    // Type constraint ensures key matches expected type
    // Compiler enforces this!
}
```

---

### 6. Information Leakage in Errors

**Vulnerable**:
```go
return fmt.Errorf("signature verification failed: invalid RSA signature for modulus %x", key.N)
// Leaks key information!
```

**Secure**:
```go
return ErrInvalidSignature // Generic error, no details
```

**Implementation**:
```go
// jwt/errors.go
var (
    ErrInvalidSignature = errors.New("invalid signature")
    ErrTokenExpired     = errors.New("token expired")
    // Generic errors only
)

// No detailed error messages that leak crypto details
```

---

### 7. JWT Size Attacks (DoS)

**Threat**: Extremely large tokens cause resource exhaustion

**Mitigation**:
```go
const MaxTokenSize = 8192 // 8KB limit

func Parse(tokenString string) (*Token, error) {
    if len(tokenString) > MaxTokenSize {
        return nil, ErrTokenTooLarge
    }
    // ...
}
```

---

### 8. Audience Confusion

**Threat**: Token for one service used on another

**Mitigation**:
```go
// Issuer MUST set audience
claims.Audience = []string{"https://api.example.com"}

// Verifier MUST check audience
opts := &jwt.VerifyOptions{
    Validation: &jwt.ValidationOptions{
        ValidateAudience: true,
        ExpectedAudience: []string{"https://api.example.com"},
    },
}
```

---

### 9. Clock Skew Attacks

**Threat**: Expired tokens accepted due to clock differences

**Mitigation**:
```go
// Allow reasonable clock skew
opts := &jwt.ValidationOptions{
    ClockSkew: 60 * time.Second, // 1 minute tolerance
}

// But not too much!
if opts.ClockSkew > 5*time.Minute {
    return errors.New("clock skew too large")
}
```

---

### 10. JWE Encryption Oracle Attacks

**Threat**: Padding oracle, invalid ciphertext analysis

**Mitigation**:
```go
// Use authenticated encryption (AES-GCM)
// GoPKI uses AES-GCM by default ✅

// AVOID: AES-CBC without authentication
```

---

## Security Checklist

### Algorithm Security

- [x] Reject 'none' algorithm
- [x] Enforce algorithm whitelist
- [x] Prevent algorithm confusion
- [x] Validate algorithm before verification
- [ ] Recommend secure algorithms (ES256, EdDSA over RS256)

### Key Management

- [x] Type-safe key handling (generics)
- [ ] Secure key storage (not in code)
- [ ] Key rotation support (via JWK kid)
- [x] Minimum key sizes enforced
  - RSA: 2048+ bits
  - ECDSA: P-256+ curves
  - HMAC: 256+ bits

### Token Validation

- [x] Expiry time validation
- [x] Not-before time validation
- [x] Issuer validation
- [x] Audience validation
- [x] Clock skew handling
- [ ] JTI uniqueness (if using)
- [ ] Revocation checking (application layer)

### Cryptographic Operations

- [x] Constant-time HMAC comparison
- [x] Secure random number generation (`crypto/rand`)
- [x] Authenticated encryption (AES-GCM)
- [x] No custom crypto (use stdlib + GoPKI)

### Error Handling

- [x] Generic error messages (no crypto details)
- [x] No information leakage
- [x] Proper error propagation

### Input Validation

- [x] Token size limits
- [x] Base64 validation
- [x] JSON validation
- [x] Nil pointer checks

---

## Secure Usage Patterns

### 1. OAuth2 / OIDC

```go
// Issuer (Auth Server)
claims := jwt.NewClaims()
claims.Issuer = "https://auth.example.com"
claims.Subject = userID
claims.Audience = []string{"https://api.example.com"}
claims.SetExpiration(15 * time.Minute)

token, _ := jwt.Sign(claims, privateKey, jwt.ES256, &jwt.SignOptions{
    KeyID: "2024-key-1", // For key rotation
})

// Resource Server
opts := &jwt.VerifyOptions{
    ExpectedAlgorithm: jwt.ES256,
    Validation: &jwt.ValidationOptions{
        ValidateIssuer:   true,
        ExpectedIssuer:   "https://auth.example.com",
        ValidateAudience: true,
        ExpectedAudience: []string{"https://api.example.com"},
    },
}

claims, err := jwt.Verify(token, publicKey, opts)
```

### 2. Internal Services (HMAC)

```go
// Shared secret (from environment/vault)
secret := []byte(os.Getenv("JWT_SECRET"))
if len(secret) < 32 {
    log.Fatal("JWT secret too short")
}

// Sign
token, _ := jwt.SignWithSecret(claims, secret, jwt.HS256)

// Verify
verified, _ := jwt.VerifyWithSecret(token, secret, opts)
```

### 3. Multi-Tenant Systems

```go
// Use kid to identify tenant
claims.Extra["tenant_id"] = tenantID

opts := &jwt.SignOptions{
    KeyID: fmt.Sprintf("tenant-%s", tenantID),
}

token, _ := jwt.Sign(claims, key, jwt.RS256, opts)

// Verifier looks up key by kid
func getPublicKey(kid string) (interface{}, error) {
    return jwksCache.Get(kid) // From JWKS endpoint
}
```

---

## Security Testing

### Automated Security Tests

```go
// Run these in CI/CD
func TestSecurityScenarios(t *testing.T) {
    t.Run("RejectNoneAlgorithm", testNoneRejection)
    t.Run("PreventAlgorithmConfusion", testAlgorithmConfusion)
    t.Run("ConstantTimeHMAC", testTimingSafety)
    t.Run("TokenSizeLimit", testSizeLimit)
    t.Run("InputValidation", testMalformedInputs)
}
```

### Penetration Testing Scenarios

1. **Algorithm Confusion**: Change alg header
2. **None Algorithm**: Use alg=none
3. **Signature Stripping**: Remove signature
4. **Token Modification**: Change claims
5. **Replay Attacks**: Reuse old tokens
6. **Timing Attacks**: Measure verification time

---

## Compliance & Standards

### OWASP JWT Cheat Sheet

- ✅ Validate algorithm
- ✅ Reject 'none'
- ✅ Short expiration
- ✅ Validate audience
- ✅ Secure key storage
- ✅ Constant-time comparison

### RFC Security Considerations

- ✅ RFC 7515 §10 (JWS Security)
- ✅ RFC 7516 §11 (JWE Security)
- ✅ RFC 7519 §10 (JWT Security)

---

## Incident Response

### If Private Key Compromised

1. **Immediate**:
   - Revoke key in JWKS
   - Generate new key
   - Update key ID

2. **Short-term**:
   - Invalidate all tokens signed with old key
   - Force re-authentication

3. **Long-term**:
   - Rotate all keys
   - Audit key access
   - Implement HSM if needed

---

## Conclusion

Security is NOT optional. Every JOSE implementation MUST:

1. ✅ Reject 'none' algorithm
2. ✅ Validate algorithms explicitly
3. ✅ Use constant-time comparison (HMAC)
4. ✅ Validate all claims (exp, aud, iss)
5. ✅ Limit token size
6. ✅ Use authenticated encryption (AES-GCM)
7. ✅ Handle errors securely (no leakage)
8. ✅ Test security scenarios

**Remember**: A secure implementation is correct + hardened against attacks.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
