# JWS (JSON Web Signature) Implementation Plan

## Overview

JWS (JSON Web Signature) provides digital signatures for JSON data. **JWT is actually a specific use case of JWS**, so most JWS functionality already exists in our JWT implementation.

**RFC**: [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)

---

## Key Insight

```
JWT = JWS (signature format) + Claims (specific payload structure)
```

Our JWT implementation already provides:
- ✅ Compact serialization (`header.payload.signature`)
- ✅ Signature algorithms (RS/ES/PS/EdDSA/HS)
- ✅ Base64URL encoding
- ✅ Integration with GoPKI signing

**JWS adds**:
- JSON serialization format (multi-signature support)
- Detached content
- Unprotected headers
- General-purpose signing (not just claims)

---

## JWS Serialization Formats

### 1. Compact Serialization (Already Done in JWT!)

```
BASE64URL(UTF8(JWS Protected Header)) ||
'.' ||
BASE64URL(JWS Payload) ||
'.' ||
BASE64URL(JWS Signature)
```

**Example**:
```
eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UifQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9
```

✅ **This is exactly what JWT does!** No new code needed.

### 2. JSON Serialization (New - For Multi-Signature)

```json
{
  "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODB9",
  "signatures": [
    {
      "protected": "eyJhbGciOiJSUzI1NiJ9",
      "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB..."
    },
    {
      "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImUxMGQwIn0",
      "header": {"jku": "https://example.com/keys"},
      "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM..."
    }
  ]
}
```

**New**: ~150 lines for JSON format support

---

## Implementation Plan

### Module Structure

```
jose/jws/
├── jws.go          # Core JWS operations
├── compact.go      # Compact serialization (thin wrapper around JWT)
├── json.go         # JSON serialization format (NEW)
├── multi.go        # Multi-signature support (NEW)
├── detached.go     # Detached content support
└── jws_test.go     # Tests
```

### 1. Compact Serialization (Reuse JWT)

```go
// jose/jws/compact.go (~30 lines)

package jws

import "github.com/jasoet/gopki/jose/jwt"

// SignCompact creates JWS compact serialization
// This is identical to JWT but doesn't require Claims structure
func SignCompact[K keypair.PrivateKey](
    payload []byte, 
    key K, 
    alg jwt.Algorithm,
    kid string,
) (string, error) {
    // Create generic claims with payload as JSON
    var payloadMap map[string]interface{}
    if err := json.Unmarshal(payload, &payloadMap); err != nil {
        // If not JSON, treat as opaque data
        payloadMap = map[string]interface{}{
            "data": base64.StdEncoding.EncodeToString(payload),
        }
    }

    claims := &jwt.Claims{Extra: payloadMap}
    
    opts := &jwt.SignOptions{KeyID: kid}
    return jwt.Sign(claims, key, alg, opts)
}

// VerifyCompact verifies JWS compact format
func VerifyCompact[K keypair.PublicKey](
    jws string, 
    key K,
) ([]byte, error) {
    verified, err := jwt.Verify(jws, key, jwt.DefaultVerifyOptions())
    if err != nil {
        return nil, err
    }

    // Extract original payload
    data, _ := json.Marshal(verified.Extra)
    return data, nil
}
```

**Lines**: ~30 (thin wrapper)

---

### 2. JSON Serialization Format (New)

```go
// jose/jws/json.go (~100 lines)

package jws

// JSONSerialization represents JWS JSON format
type JSONSerialization struct {
    Payload    string      `json:"payload"`              // Base64URL encoded
    Signatures []Signature `json:"signatures,omitempty"` // Multiple signatures
}

// Signature in JSON serialization
type Signature struct {
    Protected string                 `json:"protected,omitempty"` // Base64URL(header)
    Header    map[string]interface{} `json:"header,omitempty"`    // Unprotected header
    Signature string                 `json:"signature"`            // Base64URL(signature)
}

// SignJSON creates JWS JSON serialization with multiple signatures
func SignJSON(
    payload []byte,
    signers []Signer,
) (*JSONSerialization, error) {
    payloadB64 := base64URLEncode(payload)

    jws := &JSONSerialization{
        Payload:    payloadB64,
        Signatures: make([]Signature, 0, len(signers)),
    }

    for _, signer := range signers {
        // Create protected header
        header := map[string]interface{}{
            "alg": string(signer.Algorithm),
        }
        if signer.KeyID != "" {
            header["kid"] = signer.KeyID
        }

        headerBytes, _ := json.Marshal(header)
        protectedB64 := base64URLEncode(headerBytes)

        // Create signing input
        signingInput := protectedB64 + "." + payloadB64

        // Sign
        sig, err := signer.Sign([]byte(signingInput))
        if err != nil {
            return nil, fmt.Errorf("sign with %s: %w", signer.KeyID, err)
        }

        jws.Signatures = append(jws.Signatures, Signature{
            Protected:  protectedB64,
            Header:     signer.UnprotectedHeader,
            Signature:  base64URLEncode(sig),
        })
    }

    return jws, nil
}

// VerifyJSON verifies JWS JSON serialization
func VerifyJSON(jws *JSONSerialization, verifiers []Verifier) ([]byte, error) {
    payload, err := base64URLDecode(jws.Payload)
    if err != nil {
        return nil, fmt.Errorf("decode payload: %w", err)
    }

    // Verify at least one signature
    var verified bool
    for _, sig := range jws.Signatures {
        signingInput := sig.Protected + "." + jws.Payload
        sigBytes, _ := base64URLDecode(sig.Signature)

        for _, verifier := range verifiers {
            if verifier.Verify([]byte(signingInput), sigBytes) {
                verified = true
                break
            }
        }

        if verified {
            break
        }
    }

    if !verified {
        return nil, ErrNoValidSignature
    }

    return payload, nil
}
```

**Lines**: ~100

---

### 3. Multi-Signature Support

```go
// jose/jws/multi.go (~50 lines)

package jws

// Signer represents a JWS signer
type Signer struct {
    Key               interface{}
    Algorithm         jwt.Algorithm
    KeyID             string
    UnprotectedHeader map[string]interface{}
}

// Sign signs data
func (s *Signer) Sign(data []byte) ([]byte, error) {
    switch key := s.Key.(type) {
    case *rsa.PrivateKey:
        hash, _ := s.Algorithm.HashFunc()
        return signRSA(data, key, hash)
    case *ecdsa.PrivateKey:
        return signECDSA(data, key)
    case ed25519.PrivateKey:
        return ed25519.Sign(key, data), nil
    case []byte: // HMAC
        hash, _ := s.Algorithm.HashFunc()
        return signHMAC(data, key, hash)
    default:
        return nil, fmt.Errorf("unsupported key type")
    }
}

// Verifier represents a JWS verifier
type Verifier struct {
    Key       interface{}
    Algorithm jwt.Algorithm
    KeyID     string
}

// Verify verifies signature
func (v *Verifier) Verify(data, sig []byte) bool {
    // Similar to Sign but for verification
    switch key := v.Key.(type) {
    case *rsa.PublicKey:
        hash, _ := v.Algorithm.HashFunc()
        return verifyRSA(data, sig, key, hash)
    // ... other key types
    }
}
```

**Lines**: ~50

---

### 4. Detached Content

```go
// jose/jws/detached.go (~40 lines)

// SignDetached creates JWS with detached content
func SignDetached[K keypair.PrivateKey](
    content []byte,
    key K,
    alg jwt.Algorithm,
) (string, error) {
    // Sign normally
    jws, err := SignCompact(content, key, alg, "")
    if err != nil {
        return "", err
    }

    // Remove payload (middle part)
    parts := strings.Split(jws, ".")
    return parts[0] + ".." + parts[2], nil // header..signature
}

// VerifyDetached verifies with external content
func VerifyDetached[K keypair.PublicKey](
    jws string,
    content []byte,
    key K,
) error {
    parts := strings.Split(jws, ".")
    if len(parts) != 3 || parts[1] != "" {
        return ErrInvalidDetachedFormat
    }

    // Reconstruct full JWS with content
    contentB64 := base64URLEncode(content)
    fullJWS := parts[0] + "." + contentB64 + "." + parts[2]

    _, err := VerifyCompact(fullJWS, key)
    return err
}
```

**Lines**: ~40

---

## Usage Examples

### Compact Serialization (Same as JWT)

```go
import "github.com/jasoet/gopki/jose/jws"

// Sign arbitrary JSON data
data := []byte(`{"action": "transfer", "amount": 1000}`)
token, err := jws.SignCompact(data, rsaKey, jwt.RS256, "key-1")

// Verify
payload, err := jws.VerifyCompact(token, rsaPublicKey)
```

### Multi-Signature (JSON Format)

```go
// Multiple signers
signers := []jws.Signer{
    {
        Key:       rsaKey,
        Algorithm: jwt.RS256,
        KeyID:     "rsa-key-1",
    },
    {
        Key:       ecdsaKey,
        Algorithm: jwt.ES256,
        KeyID:     "ecdsa-key-1",
    },
}

// Sign with multiple keys
token, err := jws.SignJSON(payload, signers)

// Verify (any valid signature passes)
verifiers := []jws.Verifier{
    {Key: rsaPublicKey, Algorithm: jwt.RS256},
    {Key: ecdsaPublicKey, Algorithm: jwt.ES256},
}

data, err := jws.VerifyJSON(token, verifiers)
```

### Detached Content

```go
// Sign with detached content
largeFile := []byte("...very large content...")
detached, err := jws.SignDetached(largeFile, key, jwt.ES256)
// Returns: "header..signature" (no payload)

// Verify with external content
err = jws.VerifyDetached(detached, largeFile, publicKey)
```

---

## Code Summary

| Component | Lines | Leverages |
|-----------|-------|-----------|
| Compact format | 30 | JWT module (already done) |
| JSON format | 100 | JWT encoding utilities |
| Multi-signature | 50 | JWT signing |
| Detached content | 40 | JWT operations |
| **Total** | **220** | **JWT module** |

---

## Testing Checklist

- [ ] Compact serialization tests (reuse JWT tests)
- [ ] JSON serialization format tests
- [ ] Multi-signature verification tests
- [ ] Detached content tests
- [ ] RFC 7515 test vectors
- [ ] Interop with go-jose

---

## Conclusion

JWS implementation is straightforward because **JWT already implements compact JWS**. We only need ~220 lines for JSON serialization and multi-signature support.

**Next**: [04_JWE_PLAN.md](04_JWE_PLAN.md) for encryption support.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
