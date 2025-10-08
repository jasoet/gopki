# JWE (JSON Web Encryption) Implementation Plan

## Overview

JWE provides encryption for JSON data. **GoPKI's envelope encryption already implements the JWE pattern!** We just need to wrap it in JWE format.

**RFC**: [RFC 7516 - JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)

---

## Key Insight: Envelope Encryption IS JWE

```
GoPKI Envelope Encryption = JWE Pattern
───────────────────────────────────────
1. Generate DEK                  = Content Encryption Key (CEK)
2. Encrypt data with DEK         = AES-GCM encryption
3. Encrypt DEK with public key   = Key encryption
4. Return both                   = JWE structure
```

**GoPKI already does this** in `encryption/envelope/` (86.9% coverage)!

---

## JWE Structure

### Compact Serialization (5 parts)

```
BASE64URL(UTF8(JWE Protected Header)) ||
'.' ||
BASE64URL(JWE Encrypted Key) ||
'.' ||
BASE64URL(JWE Initialization Vector) ||
'.' ||
BASE64URL(JWE Ciphertext) ||
'.' ||
BASE64URL(JWE Authentication Tag)
```

**Example**:
```
eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe.
48V1_ALb6US04U3b.
5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji.
XFBoMYUZodetZdvTiFvSkQ
```

### JSON Serialization (Multi-Recipient)

```json
{
  "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  "unprotected": {"jku": "https://example.com/keys"},
  "recipients": [
    {
      "header": {"alg": "RSA1_5", "kid": "2011-04-29"},
      "encrypted_key": "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94..."
    },
    {
      "header": {"alg": "A128KW", "kid": "7"},
      "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    }
  ],
  "iv": "AxY8DCtDaGlsbGljb3RoZQ",
  "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
  "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
}
```

---

## Implementation Plan

### Module Structure

```
jose/jwe/
├── jwe.go          # Core JWE operations
├── compact.go      # Compact serialization
├── json.go         # JSON serialization
├── keywrap.go      # AES Key Wrap (if needed)
└── jwe_test.go     # Tests
```

### 1. Compact Serialization

```go
// jose/jwe/compact.go (~100 lines)

package jwe

import (
    "github.com/jasoet/gopki/encryption/envelope"
    "github.com/jasoet/gopki/encryption"
)

// Header represents JWE header
type Header struct {
    Algorithm          string `json:"alg"` // Key encryption algorithm
    EncryptionMethod   string `json:"enc"` // Content encryption algorithm
    KeyID              string `json:"kid,omitempty"`
}

// EncryptCompact encrypts data in JWE compact format
func EncryptCompact[K keypair.KeyPair](
    plaintext []byte,
    recipient K,
    keyAlg string,    // "RSA-OAEP", "ECDH-ES"
    encAlg string,    // "A256GCM"
) (string, error) {
    // Create header
    header := Header{
        Algorithm:        keyAlg,
        EncryptionMethod: encAlg,
    }

    headerBytes, _ := json.Marshal(header)
    headerB64 := base64URLEncode(headerBytes)

    // Use GoPKI envelope encryption (already does hybrid encryption!)
    opts := encryption.EncryptOptions{
        Algorithm: encryption.AlgorithmEnvelope,
        Format:    encryption.FormatCMS,
    }

    encrypted, err := envelope.Encrypt(plaintext, recipient, opts)
    if err != nil {
        return "", err
    }

    // Extract components from envelope encryption result
    // encrypted.Data contains: IV + Ciphertext + Tag + Wrapped Key
    iv := encrypted.Metadata["iv"].([]byte)
    ciphertext := encrypted.Data // This needs parsing from envelope result
    tag := encrypted.Metadata["tag"].([]byte)
    wrappedKey := encrypted.Recipients[0].EncryptedKey

    // Encode components
    encKeyB64 := base64URLEncode(wrappedKey)
    ivB64 := base64URLEncode(iv)
    ciphertextB64 := base64URLEncode(ciphertext)
    tagB64 := base64URLEncode(tag)

    // Return JWE compact format
    return strings.Join([]string{
        headerB64,
        encKeyB64,
        ivB64,
        ciphertextB64,
        tagB64,
    }, "."), nil
}

// DecryptCompact decrypts JWE compact format
func DecryptCompact[K keypair.KeyPair](
    jwe string,
    recipient K,
) ([]byte, error) {
    parts := strings.Split(jwe, ".")
    if len(parts) != 5 {
        return nil, ErrInvalidJWEFormat
    }

    // Decode components
    header, _ := base64URLDecode(parts[0])
    encKey, _ := base64URLDecode(parts[1])
    iv, _ := base64URLDecode(parts[2])
    ciphertext, _ := base64URLDecode(parts[3])
    tag, _ := base64URLDecode(parts[4])

    // Parse header
    var h Header
    json.Unmarshal(header, &h)

    // Reconstruct encrypted data for GoPKI envelope decryption
    encrypted := &encryption.EncryptedData{
        Algorithm: encryption.AlgorithmEnvelope,
        Data:      ciphertext,
        Recipients: []encryption.RecipientInfo{
            {EncryptedKey: encKey},
        },
        Metadata: map[string]interface{}{
            "iv":  iv,
            "tag": tag,
        },
    }

    // Use GoPKI envelope decryption
    opts := encryption.DecryptOptions{}
    return envelope.Decrypt(encrypted, recipient, opts)
}
```

**Lines**: ~100

**Key Point**: This mostly just translates between JWE format and GoPKI's envelope encryption!

---

### 2. JSON Serialization (Multi-Recipient)

```go
// jose/jwe/json.go (~120 lines)

package jwe

// JSONSerialization represents JWE JSON format
type JSONSerialization struct {
    Protected   string                 `json:"protected,omitempty"`
    Unprotected map[string]interface{} `json:"unprotected,omitempty"`
    Recipients  []Recipient            `json:"recipients"`
    IV          string                 `json:"iv"`
    Ciphertext  string                 `json:"ciphertext"`
    Tag         string                 `json:"tag"`
}

// Recipient in JSON serialization
type Recipient struct {
    Header       map[string]interface{} `json:"header,omitempty"`
    EncryptedKey string                 `json:"encrypted_key"`
}

// EncryptJSON encrypts for multiple recipients
func EncryptJSON(
    plaintext []byte,
    recipients []interface{}, // Multiple public keys
    encAlg string,
) (*JSONSerialization, error) {
    // Use GoPKI multi-recipient envelope encryption
    // (already supported in encryption/envelope!)

    opts := encryption.EncryptOptions{
        Algorithm: encryption.AlgorithmEnvelope,
    }

    // GoPKI already supports multiple recipients!
    var gopkiRecipients []keypair.KeyPair
    for _, r := range recipients {
        // Convert to GoPKI key pair
        gopkiRecipients = append(gopkiRecipients, r)
    }

    encrypted, err := envelope.EncryptMultiRecipient(
        plaintext,
        gopkiRecipients,
        opts,
    )
    if err != nil {
        return "", err
    }

    // Convert to JWE JSON format
    jwe := &JSONSerialization{
        IV:         base64URLEncode(encrypted.Metadata["iv"].([]byte)),
        Ciphertext: base64URLEncode(encrypted.Data),
        Tag:        base64URLEncode(encrypted.Metadata["tag"].([]byte)),
        Recipients: make([]Recipient, len(encrypted.Recipients)),
    }

    for i, r := range encrypted.Recipients {
        jwe.Recipients[i] = Recipient{
            Header: map[string]interface{}{
                "alg": r.Algorithm,
                "kid": r.KeyID,
            },
            EncryptedKey: base64URLEncode(r.EncryptedKey),
        }
    }

    return jwe, nil
}
```

**Lines**: ~120

---

### 3. AES Key Wrap (Optional)

```go
// jose/jwe/keywrap.go (~40 lines)

import "crypto/cipher"

// WrapKey wraps a key using AES Key Wrap (RFC 3394)
func WrapKey(kek, plainKey []byte) ([]byte, error) {
    block, err := aes.NewCipher(kek)
    if err != nil {
        return nil, err
    }
    // Use stdlib crypto/cipher.WrapKey (Go 1.24+)
    return cipher.KeyWrap(block, plainKey)
}

// UnwrapKey unwraps a key
func UnwrapKey(kek, wrappedKey []byte) ([]byte, error) {
    block, err := aes.NewCipher(kek)
    if err != nil {
        return nil, err
    }
    return cipher.KeyUnwrap(block, wrappedKey)
}
```

**Lines**: ~40

---

## Leveraging GoPKI Envelope Encryption

**Key Realization**: `encryption/envelope/` already implements JWE!

```go
// What GoPKI envelope.Encrypt() does:
func Encrypt(data, recipient, opts) (*EncryptedData, error) {
    // 1. Generate random AES key (CEK in JWE)
    aesKey := GenerateAESKey(32)

    // 2. Encrypt data with AES-GCM (same as JWE)
    encrypted := EncryptAESGCM(data, aesKey, opts)
    //   → Returns: ciphertext, IV, authentication tag

    // 3. Encrypt AES key with recipient's public key (KEK in JWE)
    wrappedKey := EncryptWithRSA(aesKey, recipient.PublicKey)
    //   → Or: ECDH key agreement + wrap

    // 4. Return all components
    return &EncryptedData{
        Data: encrypted.Ciphertext,
        Recipients: [{EncryptedKey: wrappedKey}],
        Metadata: {
            "iv": encrypted.IV,
            "tag": encrypted.Tag,
        },
    }
}
```

**This IS JWE!** We just need to:
1. Format it as `header.enckey.iv.ciphertext.tag` (compact)
2. Or format as JSON (JSON serialization)

---

## Code Summary

| Component | Lines | Leverages |
|-----------|-------|-----------|
| Compact format | 100 | `envelope.Encrypt()` |
| JSON format | 120 | `envelope.EncryptMultiRecipient()` |
| AES Key Wrap | 40 | stdlib `crypto/cipher` |
| **Total** | **260** | **Existing 86.9% tested code** |

---

## Usage Examples

### Encrypt/Decrypt (Compact)

```go
import "github.com/jasoet/gopki/jose/jwe"

// Encrypt
jweToken, err := jwe.EncryptCompact(
    plaintext,
    rsaPublicKey,
    "RSA-OAEP-256",
    "A256GCM",
)

// Decrypt
plaintext, err := jwe.DecryptCompact(jweToken, rsaPrivateKey)
```

### Multi-Recipient (JSON)

```go
// Encrypt for multiple recipients
recipients := []interface{}{
    alicePublicKey,
    bobPublicKey,
    carolPublicKey,
}

jwe, err := jwe.EncryptJSON(plaintext, recipients, "A256GCM")

// Any recipient can decrypt
plaintext, err := jwe.DecryptJSON(jweJSON, alicePrivateKey)
```

---

## Testing Checklist

- [ ] Compact serialization tests
- [ ] JSON serialization tests
- [ ] Multi-recipient tests
- [ ] Algorithm compatibility tests
- [ ] RFC 7516 test vectors
- [ ] Interop with go-jose

---

## Conclusion

JWE implementation is straightforward because **GoPKI envelope encryption already implements the JWE hybrid encryption pattern**. We only need ~260 lines to format it as JWE.

**Next**: [05_JWK_PLAN.md](05_JWK_PLAN.md) for key management.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
