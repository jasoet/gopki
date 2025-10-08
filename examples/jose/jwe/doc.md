# JWE (JSON Web Encryption) Examples

Comprehensive examples demonstrating all features of the GoPKI JWE module.

## Overview

This example demonstrates:
- Compact serialization (single recipient)
- JSON serialization (multiple recipients)
- Multi-recipient encryption
- Real-world collaboration scenarios

## Running the Example

```bash
# From repository root
go run -tags example ./examples/jose/jwe/

# Or use Task
task examples:jose:jwe
```

## What's Demonstrated

### Part 1: Compact Serialization
Single-recipient encryption in URL-safe format:
- RSA-OAEP-256 key encryption
- A256GCM content encryption
- Format: `header.enckey.iv.ciphertext.tag` (5 parts)

### Part 2: JSON Serialization
Full JSON format with rich metadata:
- Single recipient in JSON format
- Protected and unprotected headers
- Human-readable structure

### Part 3: Multi-Recipient Encryption
Same plaintext encrypted for multiple recipients:
- Each recipient gets their own encrypted DEK
- Same ciphertext for all recipients
- Independent decryption

### Part 4: Real-World Use Cases
- **Confidential M&A Document**: Board, CFO, and Legal access
- **Team Sprint Planning**: 4 team members with credentials

## Output Files

```
output/
├── jwe_compact_rsa.txt           # Compact encrypted message
├── jwe_json_single.json          # JSON single recipient
├── jwe_multi_recipient.json      # Multi-recipient encryption
├── jwe_confidential_ma.json      # M&A document
└── jwe_team_sprint.json          # Team collaboration data
```

## Key Concepts

### Hybrid Encryption (Envelope Encryption)

JWE uses hybrid encryption combining asymmetric and symmetric cryptography:

1. **Generate DEK** (Data Encryption Key): Random AES-256 key
2. **Encrypt Content**: Plaintext → Ciphertext using DEK + AES-GCM
3. **Encrypt DEK**: DEK → Encrypted Key using recipient's public key (RSA-OAEP)
4. **Distribute**: Send encrypted DEK + ciphertext

**Benefits:**
- Fast symmetric encryption for large data
- Secure key exchange via asymmetric cryptography
- Multiple recipients without re-encrypting content

### Compact vs JSON Format

**Compact (Single Recipient):**
```
eyJhbGc...  # header (base64url)
.
kR3uT5...   # encrypted key (base64url)
.
vG8hN2...   # IV (base64url)
.
cD9fK4...   # ciphertext (base64url)
.
sL2mP1...   # authentication tag (base64url)
```

**JSON (Multiple Recipients):**
```json
{
  "protected": "eyJlbmMiOiJBMjU2R0NNIn0",
  "recipients": [
    {
      "header": {"kid": "alice"},
      "encrypted_key": "..."
    },
    {
      "header": {"kid": "bob"},
      "encrypted_key": "..."
    }
  ],
  "iv": "...",
  "ciphertext": "...",
  "tag": "..."
}
```

### Multi-Recipient Pattern

```
               ┌──────────────┐
               │  Plaintext   │
               └──────┬───────┘
                      │
              Generate Random DEK
                      │
                      ▼
               ┌──────────────┐
               │  AES-256-GCM │
               │  Encryption  │
               └──────┬───────┘
                      │
              ┌───────┴───────┐
              │               │
              ▼               ▼
        ┌──────────┐    ┌──────────┐
        │Ciphertext│    │   DEK    │
        └──────────┘    └────┬─────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌─────────┐    ┌─────────┐   ┌─────────┐
        │ Alice's │    │  Bob's  │   │ Carol's │
        │ RSA Key │    │ RSA Key │   │ RSA Key │
        └────┬────┘    └────┬────┘   └────┬────┘
             │              │              │
             ▼              ▼              ▼
      ┌──────────┐   ┌──────────┐   ┌──────────┐
      │Encrypted │   │Encrypted │   │Encrypted │
      │  DEK #1  │   │  DEK #2  │   │  DEK #3  │
      └──────────┘   └──────────┘   └──────────┘

All recipients get:
- Same ciphertext
- Same IV
- Same tag
- Different encrypted DEKs
```

## Algorithm Support

### Current Implementation

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Key Encryption | RSA-OAEP-256 | RSA with OAEP padding, SHA-256 |
| Content Encryption | A256GCM | AES-256 in GCM mode |

### Future Algorithms

- ECDH-ES (Elliptic Curve Diffie-Hellman)
- A128GCM, A192GCM (smaller AES key sizes)
- Additional key wrapping algorithms

## Use Case Patterns

### 1. Confidential Document Distribution

**Scenario**: Share sensitive documents with specific individuals

```go
recipients := []keypair.GenericPublicKey{ceo, cfo, legal}
encrypted, _ := jwe.EncryptJSON(document, recipients, "A256GCM", keyAlgs, keyIDs)
```

**Benefits:**
- Only authorized recipients can decrypt
- No shared passwords
- Individual key rotation

### 2. Team Collaboration

**Scenario**: Team needs access to shared secrets (API keys, credentials)

```go
teamKeys := []keypair.GenericPublicKey{alice, bob, carol, dave}
encrypted, _ := jwe.EncryptJSON(credentials, teamKeys, "A256GCM", keyAlgs, keyIDs)
```

**Benefits:**
- Each team member uses their own key
- Add/remove team members easily
- Audit trail via key IDs

### 3. Secure Messaging

**Scenario**: Send encrypted message to specific user

```go
encrypted, _ := jwe.EncryptCompact(message, recipientKey, "RSA-OAEP-256", "A256GCM", "msg-123")
```

**Benefits:**
- Compact format for transmission
- End-to-end encryption
- Forward secrecy with ephemeral keys

## Security Considerations

### Key Size Recommendations

- **RSA**: Minimum 2048-bit (3072-bit or 4096-bit for high security)
- **AES**: 256-bit for long-term confidentiality

### Best Practices

1. **Unique IVs**: Never reuse IVs (JWE generates random IVs automatically)
2. **Authenticated Encryption**: A256GCM provides both confidentiality and authenticity
3. **Key Rotation**: Use key IDs to support key rotation
4. **Access Control**: Verify key IDs before decryption
5. **Transport Security**: Use TLS even with JWE for defense in depth

### Data Size Limits

JWE is suitable for:
- ✅ Small to medium data (< 1MB): Tokens, credentials, small documents
- ⚠️ Large data (1MB - 10MB): Works but consider streaming
- ❌ Very large data (> 10MB): Use hybrid approach (encrypt file separately, JWE for key)

## Performance Characteristics

**Encryption:**
- RSA-OAEP key encryption: ~1,000 ops/sec
- AES-256-GCM content encryption: ~100 MB/sec
- Bottleneck: RSA key encryption (not content size)

**Multi-Recipient:**
- Adding recipients is linear: O(n) RSA operations
- Content encryption happens once regardless of recipient count

**Decryption:**
- RSA-OAEP key decryption: ~1,000 ops/sec
- AES-256-GCM content decryption: ~100 MB/sec

## Example Code Snippets

### Basic Encryption/Decryption

```go
// Encrypt
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
encrypted, _ := jwe.EncryptCompact(
    plaintext,
    keyPair,
    "RSA-OAEP-256",
    "A256GCM",
    "key-id",
)

// Decrypt
decrypted, _ := jwe.DecryptCompact(encrypted, keyPair)
```

### Multi-Recipient Encryption

```go
recipients := []keypair.GenericPublicKey{alice, bob, carol}
keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256"}
keyIDs := []string{"alice", "bob", "carol"}

encrypted, _ := jwe.EncryptJSON(data, recipients, "A256GCM", keyAlgs, keyIDs)

// Each recipient decrypts independently
jwe.DecryptJSON(encrypted, aliceKey)
jwe.DecryptJSON(encrypted, bobKey)
jwe.DecryptJSON(encrypted, carolKey)
```

## Comparison with JWS

| Feature | JWE | JWS |
|---------|-----|-----|
| Purpose | Confidentiality | Integrity/Authentication |
| Output | Ciphertext | Signature |
| Recipients | Multiple (different keys) | Multiple (different signatures) |
| Plaintext | Hidden | Visible |
| Key Type | Public key encryption | Public key signing |

## Integration with GoPKI

JWE leverages GoPKI's envelope encryption module:

```go
// JWE is a thin wrapper over:
envelope.Encrypt()        // Content encryption
envelope.EncryptForMultipleRecipients()  // Multi-recipient
```

This provides:
- Battle-tested encryption (86.9% coverage)
- OpenSSL compatibility
- Optimized performance

## Related Documentation

- [JWE Module README](../../../jose/jwe/README.md)
- [Envelope Encryption](../../../encryption/envelope/README.md)
- [RFC 7516 - JWE](https://tools.ietf.org/html/rfc7516)
