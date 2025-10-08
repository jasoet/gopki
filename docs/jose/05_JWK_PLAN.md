# JWK (JSON Web Key) Implementation Plan

## Overview

JWK provides a standardized JSON format for representing cryptographic keys. This enables key distribution, rotation, and discovery (JWKS endpoints).

**RFC**: [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)

---

## JWK Format Examples

### RSA Public Key
```json
{
  "kty": "RSA",
  "use": "sig",
  "kid": "2024-rsa-key",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
  "e": "AQAB"
}
```

### ECDSA Public Key
```json
{
  "kty": "EC",
  "use": "sig",
  "kid": "2024-ec-key",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}
```

### Ed25519 Public Key
```json
{
  "kty": "OKP",
  "use": "sig",
  "kid": "2024-ed-key",
  "crv": "Ed25519",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
```

### JWK Set (JWKS)
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "rsa-2024-01",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "use": "sig",
      "kid": "ec-2024-01",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

---

## Implementation Plan

### Module Structure

```
jose/jwk/
├── jwk.go          # Core JWK types
├── import.go       # JWK → GoPKI keys
├── export.go       # GoPKI keys → JWK
├── set.go          # JWK Set (JWKS)
├── thumbprint.go   # JWK thumbprint calculation
└── jwk_test.go     # Tests
```

### 1. Core Types (`jwk.go`)

```go
// jose/jwk/jwk.go (~80 lines)

package jwk

// JWK represents a JSON Web Key
type JWK struct {
    // Common parameters
    KeyType    string   `json:"kty"`           // "RSA", "EC", "OKP", "oct"
    Use        string   `json:"use,omitempty"` // "sig" or "enc"
    KeyOps     []string `json:"key_ops,omitempty"`
    Algorithm  string   `json:"alg,omitempty"`
    KeyID      string   `json:"kid,omitempty"`

    // RSA parameters
    N string `json:"n,omitempty"` // Modulus (Base64URL)
    E string `json:"e,omitempty"` // Exponent (Base64URL)
    D string `json:"d,omitempty"` // Private exponent (Base64URL)
    P string `json:"p,omitempty"` // First prime factor
    Q string `json:"q,omitempty"` // Second prime factor

    // EC parameters
    Curve string `json:"crv,omitempty"` // "P-256", "P-384", "P-521"
    X     string `json:"x,omitempty"`   // X coordinate (Base64URL)
    Y     string `json:"y,omitempty"`   // Y coordinate (Base64URL)

    // OKP (Ed25519/X25519) parameters
    // Curve already defined above
    // X already defined above

    // Symmetric key parameter
    K string `json:"k,omitempty"` // Key value (Base64URL)
}

// Parse parses JWK JSON
func Parse(data []byte) (*JWK, error) {
    var jwk JWK
    if err := json.Unmarshal(data, &jwk); err != nil {
        return nil, err
    }
    return &jwk, nil
}

// MarshalJSON custom marshal for JWK
func (j *JWK) MarshalJSON() ([]byte, error) {
    // Only include relevant fields based on key type
    type Alias JWK
    return json.Marshal((*Alias)(j))
}
```

**Lines**: ~80

---

### 2. Import (JWK → GoPKI)

```go
// jose/jwk/import.go (~120 lines)

package jwk

import (
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "crypto/rsa"
    "math/big"

    "github.com/jasoet/gopki/keypair/algo"
)

// ToPublicKey converts JWK to Go public key
func (j *JWK) ToPublicKey() (interface{}, error) {
    switch j.KeyType {
    case "RSA":
        return j.toRSAPublicKey()
    case "EC":
        return j.toECDSAPublicKey()
    case "OKP":
        return j.toOKPPublicKey()
    default:
        return nil, fmt.Errorf("unsupported key type: %s", j.KeyType)
    }
}

// toRSAPublicKey converts to *rsa.PublicKey
func (j *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
    nBytes, err := base64URLDecode(j.N)
    if err != nil {
        return nil, fmt.Errorf("decode modulus: %w", err)
    }

    eBytes, err := base64URLDecode(j.E)
    if err != nil {
        return nil, fmt.Errorf("decode exponent: %w", err)
    }

    return &rsa.PublicKey{
        N: new(big.Int).SetBytes(nBytes),
        E: int(new(big.Int).SetBytes(eBytes).Int64()),
    }, nil
}

// toECDSAPublicKey converts to *ecdsa.PublicKey
func (j *JWK) toECDSAPublicKey() (*ecdsa.PublicKey, error) {
    curve, err := getCurve(j.Curve)
    if err != nil {
        return nil, err
    }

    xBytes, _ := base64URLDecode(j.X)
    yBytes, _ := base64URLDecode(j.Y)

    return &ecdsa.PublicKey{
        Curve: curve,
        X:     new(big.Int).SetBytes(xBytes),
        Y:     new(big.Int).SetBytes(yBytes),
    }, nil
}

// toOKPPublicKey converts to ed25519.PublicKey
func (j *JWK) toOKPPublicKey() (ed25519.PublicKey, error) {
    if j.Curve != "Ed25519" {
        return nil, fmt.Errorf("unsupported OKP curve: %s", j.Curve)
    }

    xBytes, err := base64URLDecode(j.X)
    if err != nil {
        return nil, err
    }

    return ed25519.PublicKey(xBytes), nil
}

// ToGoPKIKeyPair converts JWK to GoPKI key pair
func (j *JWK) ToGoPKIKeyPair() (interface{}, error) {
    switch j.KeyType {
    case "RSA":
        pub, _ := j.toRSAPublicKey()
        // If private key components exist
        if j.D != "" {
            priv, err := j.toRSAPrivateKey()
            if err != nil {
                return nil, err
            }
            return &algo.RSAKeyPair{
                PrivateKey: priv,
                PublicKey:  &priv.PublicKey,
            }, nil
        }
        return pub, nil

    // Similar for EC and OKP...
    }
}

func getCurve(name string) (elliptic.Curve, error) {
    switch name {
    case "P-256":
        return elliptic.P256(), nil
    case "P-384":
        return elliptic.P384(), nil
    case "P-521":
        return elliptic.P521(), nil
    default:
        return nil, fmt.Errorf("unsupported curve: %s", name)
    }
}
```

**Lines**: ~120

---

### 3. Export (GoPKI → JWK)

```go
// jose/jwk/export.go (~100 lines)

package jwk

// FromPublicKey creates JWK from Go public key
func FromPublicKey(key interface{}, use, kid string) (*JWK, error) {
    switch k := key.(type) {
    case *rsa.PublicKey:
        return fromRSAPublicKey(k, use, kid)
    case *ecdsa.PublicKey:
        return fromECDSAPublicKey(k, use, kid)
    case ed25519.PublicKey:
        return fromEd25519PublicKey(k, use, kid)
    default:
        return nil, fmt.Errorf("unsupported key type")
    }
}

// fromRSAPublicKey creates RSA JWK
func fromRSAPublicKey(key *rsa.PublicKey, use, kid string) (*JWK, error) {
    return &JWK{
        KeyType: "RSA",
        Use:     use,
        KeyID:   kid,
        N:       base64URLEncode(key.N.Bytes()),
        E:       base64URLEncode(big.NewInt(int64(key.E)).Bytes()),
    }, nil
}

// fromECDSAPublicKey creates EC JWK
func fromECDSAPublicKey(key *ecdsa.PublicKey, use, kid string) (*JWK, error) {
    curveName, err := getCurveName(key.Curve)
    if err != nil {
        return nil, err
    }

    return &JWK{
        KeyType: "EC",
        Use:     use,
        KeyID:   kid,
        Curve:   curveName,
        X:       base64URLEncode(key.X.Bytes()),
        Y:       base64URLEncode(key.Y.Bytes()),
    }, nil
}

// fromEd25519PublicKey creates OKP JWK
func fromEd25519PublicKey(key ed25519.PublicKey, use, kid string) (*JWK, error) {
    return &JWK{
        KeyType: "OKP",
        Use:     use,
        KeyID:   kid,
        Curve:   "Ed25519",
        X:       base64URLEncode([]byte(key)),
    }, nil
}

// FromGoPKIKeyPair creates JWK from GoPKI key pair
func FromGoPKIKeyPair(keyPair interface{}, use, kid string) (*JWK, error) {
    switch kp := keyPair.(type) {
    case *algo.RSAKeyPair:
        return fromRSAPublicKey(kp.PublicKey, use, kid)
    case *algo.ECDSAKeyPair:
        return fromECDSAPublicKey(kp.PublicKey, use, kid)
    case *algo.Ed25519KeyPair:
        return fromEd25519PublicKey(kp.PublicKey, use, kid)
    default:
        return nil, fmt.Errorf("unsupported key pair type")
    }
}

func getCurveName(curve elliptic.Curve) (string, error) {
    switch curve {
    case elliptic.P256():
        return "P-256", nil
    case elliptic.P384():
        return "P-384", nil
    case elliptic.P521():
        return "P-521", nil
    default:
        return "", fmt.Errorf("unsupported curve")
    }
}
```

**Lines**: ~100

---

### 4. JWK Set Support (`set.go`)

```go
// jose/jwk/set.go (~60 lines)

package jwk

// JWKSet represents a JWK Set (JWKS)
type JWKSet struct {
    Keys []JWK `json:"keys"`
}

// ParseSet parses JWKS JSON
func ParseSet(data []byte) (*JWKSet, error) {
    var set JWKSet
    if err := json.Unmarshal(data, &set); err != nil {
        return nil, err
    }
    return &set, nil
}

// FindByKeyID finds key by ID
func (s *JWKSet) FindByKeyID(kid string) (*JWK, error) {
    for i := range s.Keys {
        if s.Keys[i].KeyID == kid {
            return &s.Keys[i], nil
        }
    }
    return nil, fmt.Errorf("key not found: %s", kid)
}

// FindByUse finds keys by use
func (s *JWKSet) FindByUse(use string) []JWK {
    var keys []JWK
    for _, k := range s.Keys {
        if k.Use == use {
            keys = append(keys, k)
        }
    }
    return keys
}

// Add adds key to set
func (s *JWKSet) Add(key *JWK) {
    s.Keys = append(s.Keys, *key)
}

// Remove removes key by ID
func (s *JWKSet) Remove(kid string) bool {
    for i := range s.Keys {
        if s.Keys[i].KeyID == kid {
            s.Keys = append(s.Keys[:i], s.Keys[i+1:]...)
            return true
        }
    }
    return false
}

// MarshalJSON serializes JWK Set
func (s *JWKSet) MarshalJSON() ([]byte, error) {
    return json.Marshal(map[string]interface{}{
        "keys": s.Keys,
    })
}
```

**Lines**: ~60

---

### 5. JWK Thumbprint (`thumbprint.go`)

```go
// jose/jwk/thumbprint.go (~40 lines)

package jwk

import (
    "crypto"
    "encoding/json"
    "sort"
)

// Thumbprint calculates JWK thumbprint (RFC 7638)
func (j *JWK) Thumbprint(hash crypto.Hash) ([]byte, error) {
    // Create canonical JSON with only required fields
    canonical := j.canonicalJSON()

    // Sort keys
    keys := make([]string, 0, len(canonical))
    for k := range canonical {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    // Build canonical JSON string
    var buf bytes.Buffer
    buf.WriteString("{")
    for i, k := range keys {
        if i > 0 {
            buf.WriteString(",")
        }
        fmt.Fprintf(&buf, `"%s":"%s"`, k, canonical[k])
    }
    buf.WriteString("}")

    // Hash
    h := hash.New()
    h.Write(buf.Bytes())
    return h.Sum(nil), nil
}

// canonicalJSON extracts required fields for thumbprint
func (j *JWK) canonicalJSON() map[string]string {
    m := map[string]string{
        "kty": j.KeyType,
    }

    switch j.KeyType {
    case "RSA":
        m["e"] = j.E
        m["n"] = j.N
    case "EC":
        m["crv"] = j.Curve
        m["x"] = j.X
        m["y"] = j.Y
    case "OKP":
        m["crv"] = j.Curve
        m["x"] = j.X
    }

    return m
}
```

**Lines**: ~40

---

## Code Summary

| Component | Lines | Complexity |
|-----------|-------|------------|
| Core types | 80 | Low |
| Import (JWK → GoPKI) | 120 | Medium |
| Export (GoPKI → JWK) | 100 | Medium |
| JWK Set | 60 | Low |
| Thumbprint | 40 | Low |
| **Total** | **400** | **Medium** |

---

## Usage Examples

### Export GoPKI Key to JWK

```go
import "github.com/jasoet/gopki/jose/jwk"

// Export public key
jwkData, err := jwk.FromGoPKIKeyPair(rsaKeyPair, "sig", "rsa-2024-01")

// Serialize to JSON
jsonData, _ := json.MarshalIndent(jwkData, "", "  ")
fmt.Println(string(jsonData))
```

### Import JWK to GoPKI

```go
// Parse JWK JSON
jwkData, err := jwk.Parse(jsonData)

// Convert to GoPKI key pair
keyPair, err := jwkData.ToGoPKIKeyPair()

// Use with signing
signature, _ := jwt.Sign(claims, keyPair, jwt.RS256, nil)
```

### JWK Set (JWKS)

```go
// Create JWKS
jwks := &jwk.JWKSet{}

// Add keys
jwks.Add(jwk.FromGoPKIKeyPair(rsaKey, "sig", "rsa-1"))
jwks.Add(jwk.FromGoPKIKeyPair(ecKey, "sig", "ec-1"))

// Serialize
data, _ := json.Marshal(jwks)

// Parse JWKS
parsed, _ := jwk.ParseSet(data)

// Find key by ID
key, _ := parsed.FindByKeyID("rsa-1")
```

### Calculate Thumbprint

```go
thumbprint, err := jwkData.Thumbprint(crypto.SHA256)
thumbprintB64 := base64.URLEncoding.EncodeToString(thumbprint)
// Use as key ID
```

---

## Testing Checklist

- [ ] RSA import/export round-trip
- [ ] ECDSA import/export round-trip
- [ ] Ed25519 import/export round-trip
- [ ] JWK Set operations
- [ ] Thumbprint calculation
- [ ] RFC 7517 test vectors
- [ ] Interop with go-jose

---

## Conclusion

JWK implementation provides key distribution and management capabilities. ~400 lines of code enable full JWK/JWKS support for GoPKI keys.

**Next**: [07_TESTING.md](07_TESTING.md) for testing strategy.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
