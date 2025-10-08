# JWS (JSON Web Signature) Examples

Comprehensive examples demonstrating all features of the GoPKI JWS module.

## Overview

This example demonstrates:
- Compact serialization (URL-safe, single signature)
- JSON serialization (multiple signatures)
- Multi-signature support
- Detached content signatures
- Real-world use cases

## Running the Example

```bash
# From repository root
go run -tags example ./examples/jose/jws/

# Or use Task
task examples:jose:jws
```

## What's Demonstrated

### Part 1: Compact Serialization
URL-safe format with single signature:
- RS256, ES256, EdDSA (public key algorithms)
- HS256 (HMAC symmetric algorithm)
- Format: `header.payload.signature` (3 parts separated by `.`)

### Part 2: JSON Serialization
Full JSON format supporting rich metadata:
- Single signature in JSON format
- Protected and unprotected headers
- Human-readable structure

### Part 3: Multi-Signature
Multiple parties signing the same content:
- CEO, CFO, CTO signing a document
- Each with different algorithms (RS256, ES256, EdDSA)
- Independent verification of each signature

### Part 4: Detached Content
Signing large files without embedding them:
- Signature and document stored separately
- Useful for large PDFs, videos, datasets
- Efficient verification

### Part 5: Real-World Use Cases
- **Legal Document Signing**: HR and manager sign employment contract
- **Approval Chain**: Multi-level budget approval workflow

## Output Files

```
output/
├── jws_compact_rs256.txt         # Compact RS256 signature
├── jws_compact_es256.txt         # Compact ES256 signature
├── jws_compact_eddsa.txt         # Compact EdDSA signature
├── jws_compact_hs256.txt         # Compact HMAC signature
├── jws_json_single.json          # JSON single signature
├── jws_multi_signature.json      # Multi-party signature
├── jws_detached_signature.txt    # Detached signature
├── jws_detached_document.txt     # Original document
├── jws_contract_signed.json      # Signed employment contract
└── jws_approval_chain.json       # Multi-level approval
```

## Key Concepts

### Compact vs JSON Serialization

**Compact (for URLs/Headers):**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS1rZXkifQ.VGhpcyBpcyBhIHRlc3Q.signature...
```
- URL-safe
- Single signature only
- Minimal overhead
- Used in HTTP headers

**JSON (for Rich Metadata):**
```json
{
  "payload": "VGhpcyBpcyBhIHRlc3Q",
  "signatures": [
    {
      "protected": "eyJhbGciOiJSUzI1NiJ9",
      "header": {"kid": "rsa-key"},
      "signature": "..."
    }
  ]
}
```
- Multiple signatures
- Rich metadata
- Human-readable
- Used in documents

### Multi-Signature Benefits

1. **Non-repudiation**: Each party independently signs
2. **Flexible Verification**: Verify any subset of signatures
3. **Different Algorithms**: Mix RSA, ECDSA, Ed25519
4. **Audit Trail**: Timestamps and roles in headers

### Detached Content Benefits

1. **Efficiency**: Don't duplicate large files
2. **Flexibility**: Distribute signature and content separately
3. **Streaming**: Sign/verify without loading entire file
4. **Compatibility**: Original file unchanged

## Algorithm Selection

| Use Case | Recommended | Reason |
|----------|------------|--------|
| API calls | Compact + EdDSA/ES256 | Fast, small signatures |
| Documents | JSON + RS256 | Wide compatibility |
| Multi-party | JSON + Mixed | Different parties, different keys |
| Large files | Detached + RS256/ES256 | Don't embed content |
| Internal | Compact + HS256 | Shared secret, fast |

## Example Code Snippets

### Basic Compact Signature

```go
// Sign
keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
signature, _ := jws.SignCompact(payload, keyPair, "ES256", "my-key")

// Verify
verified, _ := jws.VerifyCompact(signature, keyPair)
```

### Multi-Signature

```go
signatures := []jws.Signature{
    {Signer: alice, Algorithm: "RS256", KeyID: "alice"},
    {Signer: bob, Algorithm: "ES256", KeyID: "bob"},
}

signed, _ := jws.SignJSON(document, signatures)

// Each party verifies independently
jws.VerifyJSON(signed, alice)
jws.VerifyJSON(signed, bob)
```

### Detached Signature

```go
// Sign large file
signature, _ := jws.SignDetached(largeFile, keyPair, "RS256", "signer")

// Distribute signature and file separately
// Later, verify:
verified, _ := jws.VerifyDetached(signature, largeFile, keyPair)
```

## Security Considerations

1. **Algorithm Confusion**: JWS validates algorithm matches key type
2. **Key ID**: Use unique key IDs for key rotation
3. **HMAC Secrets**: Minimum 32 bytes, never hardcode
4. **Timestamps**: Include in unprotected headers for audit trail
5. **Payload Validation**: Always validate payload content after verification

## Comparison with JWT

| Feature | JWT | JWS |
|---------|-----|-----|
| Purpose | Authentication tokens | Generic signatures |
| Payload | JSON claims | Any binary data |
| Validation | Claims + signature | Signature only |
| Format | Always compact | Compact or JSON |
| Multi-sig | No | Yes (JSON format) |

## Related Documentation

- [JWS Module README](../../../jose/jws/README.md)
- [JWT Examples](../jwt/doc.md)
- [RFC 7515 - JWS](https://tools.ietf.org/html/rfc7515)
