# Vault Integration - Foundation Analysis

**Date:** 2025-10-27
**Branch:** `feature/vault-integration`
**Purpose:** Document key findings before Phase 1 implementation

---

## 1. context.Context Usage Analysis

### Current State: NO Context Usage in GoPKI ❌

**Finding:** GoPKI does **NOT** currently use `context.Context` anywhere in the codebase.

**Evidence:**
```bash
$ grep -r "context.Context" --include="*.go" .
# No matches (except in our new documentation)

$ grep -r "import.*context" --include="*.go" .
# No matches
```

**Analysis:**
- ✅ All current GoPKI operations are **synchronous** and **local**
- ✅ No network I/O in existing modules
- ✅ No long-running operations that benefit from cancellation
- ✅ Consistent with the library's design: pure cryptographic operations

### Recommendation for Vault Module

**DO use context.Context in Vault module** for the following reasons:

1. **Network Operations:**
   - HTTP requests to Vault server
   - Connection timeout handling
   - Request cancellation

2. **Modern Go Patterns:**
   - Standard practice for network I/O since Go 1.7
   - Enables graceful shutdown
   - Better integration with other Go services

3. **User Control:**
   - Caller can set timeouts
   - Caller can cancel operations
   - Better error handling

**Recommended Pattern:**

```go
// Vault module should use context for ALL network operations
func (c *Client) IssueCertificate(
    ctx context.Context, // REQUIRED for network calls
    role string,
    opts *IssueOptions,
) (*cert.Certificate, error) {
    // Create HTTP request with context
    req, err := http.NewRequestWithContext(ctx, "POST", url, body)
    if err != nil {
        return nil, fmt.Errorf("vault: create request: %w", err)
    }

    // Make request (respects context cancellation/timeout)
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("vault: issue certificate: %w", err)
    }
    // ...
}
```

**Usage Example:**

```go
// User controls timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

cert, err := vaultClient.IssueCertificate(ctx, "web-server", opts)
if err != nil {
    // Could be timeout, cancellation, or Vault error
    log.Printf("Failed: %v", err)
}
```

### CSR Functions: NO Context Needed ✅

**Decision:** Do NOT add context to CSR functions in cert module.

**Rationale:**
1. CSR generation is a **local, synchronous** operation
2. Completes in milliseconds (no timeout needed)
3. No network I/O
4. Consistent with other cert module functions
5. Would break consistency with existing GoPKI APIs

**Keep As-Is:**
```go
// NO context - pure cryptographic operation
func CreateCSR[T keypair.KeyPair](
    keyPair T,
    request CSRRequest,
) (*CertificateSigningRequest, error)
```

---

## 2. Envelope Encryption Cycle Analysis

### Test File: `encryption/envelope/cms_cycle_test.go`

**Purpose:** Tests the complete envelope encryption CMS encoding/decoding cycle.

### Understanding Issue #1 (RESOLVED ✅)

**What Issue #1 Was:**
- **Problem:** Duplicate certificates in PKCS#7 signatures
- **Impact:** 42% larger signature sizes (~1,400 bytes → ~820 bytes)
- **Fixed In:** v1.18.0 (commit: 74f73e6)
- **Test:** `signing/signing_test.go:1682` - regression prevention

**NOT Related to Envelope Encryption:**
The envelope encryption cycle tests are separate from Issue #1. They test a different scenario.

### Envelope Encryption CMS Cycle

**What the Test Checks:**

```
Step 1: EncryptWithCertificate()
        ↓ (creates envelope: encrypted DEK + AES-GCM encrypted data)
Step 2: EncodeData() → CMS format
        ↓ (serializes to PKCS#7 EnvelopedData)
Step 3: DecodeDataWithKey() ← Parse CMS
        ↓ (should preserve envelope structure)
Step 4: Decrypt()
        ↓ (decrypt the AES-encrypted data using DEK)
Result: Original plaintext
```

**Critical Assertion:**

```go
// After Step 3 (decode from CMS):
// decoded.Data should STILL BE ENCRYPTED (AES-encrypted)
// decoded.IV should be preserved
// decoded.Tag should be preserved
// decoded.Recipients[].EncryptedKey should be preserved
//
// The bug would be if decoded.Data contains PLAINTEXT here
// That would mean DecodeDataWithKey() prematurely decrypted everything
```

### Test Results Analysis

**Test Function:** `TestCertificateEnvelopeEncryptionWithCMSCycle`

Looking at the test code (lines 57-155), the test has two scenarios:

1. **"RSA Certificate - Full CMS Cycle"** (lines 65-133)
   - Tests the complete cycle with CMS encoding
   - Lines 111-121: Checks that envelope structure is preserved
   - Lines 124-132: Attempts final decryption

2. **"Without CMS Cycle - Should Work"** (lines 135-154)
   - Tests direct encrypt → decrypt (no CMS)
   - This is known to work

**Key Comment from Test:**

```go
// These assertions will FAIL with the current implementation:
// The bug is that DecodeFromCMS decrypts the entire envelope,
// so decoded.Data contains plaintext instead of AES-encrypted data
assert.NotNil(t, decoded.IV, "IV should be preserved after CMS decode")
```

### OpenSSL Compatible Mode

**Test Function:** `TestOpenSSLCompatibleMode` (lines 219-342)

- Tests `opts.OpenSSLCompatible = true` flag
- **RSA only:** ECDSA and Ed25519 correctly rejected
- Stores raw PKCS#7 EnvelopedData in `encrypted.Data`
- Uses metadata flag: `openssl_compatible: true`
- Special handling: When decoded, sets `already_decrypted: true`

**Important for Vault Integration:**

```go
// When OpenSSL mode is used:
encrypted.Metadata["openssl_compatible"] = true
// After decode:
decoded.Metadata["already_decrypted"] = true
```

---

## 3. Implications for Vault Integration

### 3.1 Context Usage ✅

**Decision:** Use context in ALL Vault network operations.

```go
// All Vault functions should follow this pattern:
func (c *Client) <Operation>(
    ctx context.Context,
    // ... other params
) (<Return>, error) {
    req, err := http.NewRequestWithContext(ctx, ...)
    // ...
}
```

**Functions that MUST use context:**
- `IssueCertificate(ctx, ...)`
- `SignCSR(ctx, ...)`
- `GenerateRootCA(ctx, ...)`
- `Health(ctx)`
- `ValidateConnection(ctx)`
- All HTTP operations

### 3.2 Envelope Encryption Testing ✅

**Test Plan:** When testing Vault-issued certificates with envelope encryption:

1. **Test: Direct Encrypt/Decrypt**
   ```go
   cert := vaultClient.IssueCertificate(...)
   encrypted := encryption.EncryptWithCertificate(data, cert, opts)
   decrypted := encryption.Decrypt(encrypted, keyPair, decryptOpts)
   // Should work ✅
   ```

2. **Test: Full CMS Cycle**
   ```go
   cert := vaultClient.IssueCertificate(...)
   encrypted := encryption.EncryptWithCertificate(data, cert, opts)
   cms := encryption.EncodeData(encrypted)
   decoded := encryption.DecodeDataWithKey(cms, cert, privateKey)
   decrypted := encryption.Decrypt(decoded, keyPair, decryptOpts)
   // Test envelope structure preservation
   ```

3. **Test: OpenSSL Compatible Mode**
   ```go
   opts := encryption.DefaultEncryptOptions()
   opts.OpenSSLCompatible = true
   encrypted := encryption.EncryptWithCertificate(data, cert, opts)
   // Should work with Vault RSA certs
   // Should fail with ECDSA/Ed25519 certs
   ```

**Test File:** Create `vault/integration_envelope_test.go` in Phase 3.

### 3.3 Certificate Limitations ⚠️

**Ed25519 Encryption Limitation:**

From CLAUDE.md:
> "Document limitations clearly (e.g., Ed25519 certificate encryption)"

**Recommendation:** Add validation in type conversion:

```go
func VaultCertToGoPKI(vaultCert *VaultCertificate) (*cert.Certificate, error) {
    cert, err := parseCertificate(vaultCert)
    if err != nil {
        return nil, err
    }

    // Check for known limitations
    if cert.PublicKeyAlgorithm == x509.Ed25519 {
        // Ed25519 certificates cannot be used for envelope encryption
        // See docs/ALGORITHMS.md for details
        log.Warn("Ed25519 certificate: envelope encryption not supported")
    }

    return cert, nil
}
```

---

## 4. Implementation Guidelines for Vault Module

### 4.1 Error Wrapping Convention

**Pattern:** Use consistent error wrapping format.

```go
// ✅ GOOD - GoPKI convention
fmt.Errorf("vault: issue certificate: %w", err)
fmt.Errorf("vault: sign CSR: %w", err)
fmt.Errorf("vault: create request: %w", err)

// ❌ BAD - Too verbose
fmt.Errorf("vault: certificate issuance failed: %w", err)
fmt.Errorf("vault: operation failed: %w", err)
```

### 4.2 Type Conversion Guidelines

**Vault → GoPKI:**
```go
func VaultCertToGoPKI(vaultCert *VaultCertificate) (*cert.Certificate, error) {
    // Parse PEM
    // Check limitations (Ed25519)
    // Validate certificate
    // Return cert.Certificate
}
```

**GoPKI → Vault:**
```go
func GoPKICertToVault(c *cert.Certificate) (*VaultCertificate, error) {
    // Extract PEM data
    // Create Vault-compatible structure
}
```

### 4.3 Health Check Pattern

```go
// Add health check for connection validation
func (c *Client) Health(ctx context.Context) error {
    req, _ := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/sys/health", nil)
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("vault: health check: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("vault: unhealthy (status %d)", resp.StatusCode)
    }
    return nil
}

func (c *Client) ValidateConnection(ctx context.Context) error {
    if err := c.Health(ctx); err != nil {
        return fmt.Errorf("vault: connection validation: %w", err)
    }
    // Optionally test authentication
    return nil
}
```

### 4.4 OpenSSL Compatibility

**Test with Vault-issued RSA certificates:**
```go
// Phase 3: Add OpenSSL compatibility test
func TestVaultCertOpenSSLCompatibility(t *testing.T) {
    cert := issueVaultRSACert()

    opts := encryption.DefaultEncryptOptions()
    opts.OpenSSLCompatible = true

    encrypted := encryption.EncryptWithCertificate(data, cert, opts)
    // Verify OpenSSL can decrypt this

    decrypted := encryption.Decrypt(encrypted, keyPair, decryptOpts)
    assert.Equal(t, data, decrypted)
}
```

---

## 5. Phase 1 Implementation Checklist

### Before Starting Phase 1:
- [x] CSR APIs implemented
- [x] Context usage pattern documented
- [x] Envelope encryption cycle understood
- [ ] Vault module structure created

### Phase 1 Core (Week 1.5):

**Day 1-2: Setup**
- [ ] Create `vault/` module structure
- [ ] Define core types (`config.go`, `types.go`, `errors.go`)
- [ ] Implement HTTP client with context support
- [ ] Add TLS configuration
- [ ] Implement `Health(ctx)` and `ValidateConnection(ctx)`

**Day 3-5: Certificate Operations**
- [ ] Implement `IssueCertificate(ctx, ...)` API
- [ ] Implement `IssueCertificateWithKeyPair(ctx, ...)` with generics
- [ ] Implement `SignCSR(ctx, ...)` API
- [ ] Add certificate retrieval (`GetCertificate(ctx, ...)`, `ListCertificates(ctx)`)
- [ ] Implement `integration.go` type conversions
- [ ] Add Ed25519 limitation check

**Day 6-7: Testing**
- [ ] Unit tests with HTTP mocks (no external deps)
- [ ] Type conversion tests
- [ ] Error handling tests
- [ ] Initial README.md

**Deliverables:**
- Working certificate issue/sign operations with context
- Type-safe integration with GoPKI
- 70%+ test coverage
- HTTP mock tests (no real Vault needed)

---

## 6. Key Decisions

### Decision 1: Use context.Context in Vault Module ✅

**Rationale:**
- Network I/O requires timeout/cancellation
- Standard Go practice for HTTP operations
- User control over timeouts
- Better integration with other services

**Impact:** All Vault network functions accept `ctx context.Context` as first parameter.

### Decision 2: Do NOT Add Context to CSR Functions ❌

**Rationale:**
- CSR generation is local, synchronous
- Consistent with existing cert module
- No breaking changes to GoPKI patterns
- No network I/O

**Impact:** CSR functions remain unchanged, no context parameter.

### Decision 3: Test Envelope Encryption in Phase 3 📅

**Rationale:**
- Envelope encryption tests are integration tests
- Need working Vault client first (Phase 1)
- Need CA management (Phase 2)
- Complex test scenario (Phase 3 focus)

**Impact:** Create `vault/integration_envelope_test.go` in Phase 3 with:
- Direct encrypt/decrypt test
- Full CMS cycle test
- OpenSSL compatible mode test

### Decision 4: Add Validation for Ed25519 Limitation ⚠️

**Rationale:**
- Ed25519 certs cannot be used for envelope encryption
- Warn users early to avoid confusion
- Document in type conversion

**Impact:** Add check in `VaultCertToGoPKI()` with warning log.

---

## 7. Testing Strategy

### Phase 1 Tests (Unit Tests)

**No External Dependencies:**
- HTTP mock testing with `httptest.NewServer()`
- Mock Vault responses (JSON files in `testdata/`)
- Type conversion tests
- Error handling tests

**Example:**
```go
func TestIssueCertificate(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        w.Write([]byte(mockVaultResponse))
    }))
    defer server.Close()

    client := createTestClient(server.URL)
    ctx := context.Background()

    cert, err := client.IssueCertificate(ctx, "test-role", opts)
    assert.NoError(t, err)
    assert.NotNil(t, cert)
}
```

### Phase 3 Tests (Integration Tests)

**With Real Vault (Build Tag):**
```go
//go:build vault
// +build vault

func TestRealVaultIntegration(t *testing.T) {
    // Requires: vault server -dev
    client := setupRealVaultClient()
    // ... integration tests
}
```

---

## 8. Documentation Plan

### Files to Create:

1. **`vault/README.md`** - Module overview and API reference
2. **`vault/doc.md`** - Detailed usage guide
3. **`vault/examples/`** - Working code examples
4. **`docs/VAULT_INTEGRATION.md`** - Deep dive
5. **`docs/VAULT_SECURITY.md`** - Security best practices

### Update Files:

1. **`README.md`** - Add vault module to overview
2. **`docs/ARCHITECTURE.md`** - Add vault integration diagram
3. **`docs/AI_NAVIGATION.md`** - Add vault navigation section
4. **`CLAUDE.md`** - Add vault development commands

---

## 9. Timeline Estimate

### Foundation Work: ✅ COMPLETE (1 hour)
- CSR implementation
- Context analysis
- Envelope encryption review

### Phase 1: 1.5 weeks (Revised from 1 week)
- Setup and HTTP client: 2 days
- Certificate operations: 3 days
- Testing and docs: 2 days

**Reason for Revision:** Adding context support + health checks requires more time.

### Remaining Phases: As planned in original timeline

---

## 10. Next Immediate Steps

1. **Create vault/ module structure** (15 minutes)
   - Directory layout
   - Placeholder files
   - Basic types

2. **Commit foundation analysis** (5 minutes)
   - This document
   - Updated plan

3. **Begin Phase 1 implementation** (starts next)
   - Start with `config.go` and `types.go`
   - Implement HTTP client with context
   - Add health check

---

## References

- **Envelope Test:** `encryption/envelope/cms_cycle_test.go`
- **Issue #1 Fix:** Commit `74f73e6` (v1.18.0)
- **OpenSSL Compat:** `encryption/envelope/envelope.go:520-600`
- **Context Pattern:** Standard Go `net/http` with `context.Context`
- **GoPKI Patterns:** `cert/`, `keypair/`, `signing/` modules

---

**Status:** ✅ Foundation analysis complete
**Next:** Create vault/ module structure
**Ready for:** Phase 1 implementation

---

*Document created: 2025-10-27*
*Author: AI Assistant (Claude)*
*Purpose: Document foundation findings for Vault integration Phase 1*
