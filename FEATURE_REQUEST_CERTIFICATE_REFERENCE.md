# Feature Request: Certificate Reference Mode for Minimal Signatures

**Status:** Proposed
**Priority:** Medium
**Effort:** 4-6 hours
**Expected Impact:** 85-90% signature size reduction for constrained environments

---

## Overview

Add support for **certificate reference mode** in PKCS#7 signatures, allowing creation of minimal signatures (~100-150 bytes) by referencing certificates instead of embedding them. This is particularly valuable for QR codes, IoT devices, and bandwidth-constrained environments.

---

## Background

### Current State (After Issue #1-3 Fixes)

**Implemented (v1.18.0):**
- ✅ Fixed duplicate certificate bug (Issue #1) - 42% size reduction
- ✅ Auto-extraction of certificates from PKCS#7 (Issue #2)
- ✅ Detached signature flag works correctly (Issue #3)

**Current Signature Sizes:**
```
RSA-2048:    ~820 bytes  (PKCS#7 + full certificate)
ECDSA-P256:  ~650 bytes  (PKCS#7 + full certificate)
Ed25519:     ~620 bytes  (PKCS#7 + full certificate)
```

**Size Breakdown:**
- PKCS#7 structure: ~50 bytes
- Signature value: ~70-256 bytes (algorithm dependent)
- Signed attributes: ~80 bytes
- Certificate: **~500-600 bytes** ← Largest component

### Problem Statement

For size-constrained use cases, even optimized signatures are too large:

**Use Case: Event Ticket QR Codes**
```
Ticket payload:     98 bytes (MessagePack)
Signature (current): 650 bytes (ECDSA-P256)
Total (Base64):    ~1,000 bytes
QR Version:        25-30 (hard to scan from distance)

TARGET:            ~300-400 bytes
QR Version:        7-10 (optimal scanning distance)
```

**Other Constrained Environments:**
- IoT sensor data transmission (battery/bandwidth limited)
- Mobile apps with poor connectivity
- Embedded systems with storage constraints
- NFC tags with size limits

---

## Proposed Solution

### Certificate Mode Options

Add a new `CertificateMode` field to `SignOptions`:

```go
// CertificateMode determines how certificate information is included
type CertificateMode string

const (
    // CertModeEmbed includes the full X.509 certificate in PKCS#7 (default)
    // Size: 500-600 bytes per certificate
    // Use: When verifier doesn't have access to certificate store
    CertModeEmbed CertificateMode = "embed"

    // CertModeReference includes only issuer DN + serial number
    // Size: ~50 bytes
    // Use: When verifier has access to trusted certificate store
    // Security: Requires authenticated certificate lookup
    CertModeReference CertificateMode = "reference"

    // CertModeNone omits certificate information entirely
    // Size: ~0 bytes
    // Use: Advanced use cases only (not recommended for production)
    // Security: Verifier must determine certificate through other means
    CertModeNone CertificateMode = "none"
)
```

### API Changes

#### Signing Options

```go
type SignOptions struct {
    // ... existing fields ...
    HashAlgorithm      crypto.Hash
    Format             SignatureFormat
    Detached           bool

    // DEPRECATED: Use CertificateMode instead
    // Kept for backward compatibility (maps to CertModeEmbed)
    IncludeCertificate bool
    IncludeChain       bool

    // NEW: Certificate handling mode
    // - "embed" (default): Full certificate included (~600 bytes)
    // - "reference": Only issuer+serial (~50 bytes, requires cert store)
    // - "none": No certificate info (advanced use only)
    CertificateMode CertificateMode

    ExtraCertificates  []*x509.Certificate
}
```

#### Verification Options

```go
type VerifyOptions struct {
    // ... existing fields ...
    VerifyChain      bool
    Roots            *x509.CertPool
    Intermediates    *x509.CertPool
    CurrentTime      time.Time

    // NEW: Certificate store for reference mode
    // When signature uses CertModeReference, verifier looks up
    // certificate from this store using issuer+serial
    CertificateStore CertificateStore
}

// CertificateStore interface for certificate lookup
type CertificateStore interface {
    // GetCertificate retrieves certificate by issuer DN and serial number
    // Returns ErrCertificateNotFound if not in store
    GetCertificate(issuerDN string, serialNumber *big.Int) (*x509.Certificate, error)
}
```

### Size Comparison

| Mode | Signature Size | Reduction | QR Version | Use Case |
|------|---------------|-----------|------------|----------|
| **Current (embed)** | 650 bytes | Baseline | 25-30 | General purpose, no cert store |
| **Reference** | ~150 bytes | **77%** | **5-6** | **QR codes, IoT with cert registry** |
| **None** | ~100 bytes | 85% | 3-4 | Advanced/experimental only |

**Example: Ticket QR Code with Reference Mode**
```
Ticket payload:        98 bytes (MessagePack)
Signature (reference): 150 bytes (issuer+serial only)
Total (Base64):       ~330 bytes
QR Version:           7-8 ✅ (optimal for mobile scanning)
```

---

## Implementation Design

### Phase 1: Core Implementation (3-4 hours)

#### 1.1 Update Signing Logic (`signing/signer.go`)

```go
func SignDocument[T keypair.KeyPair](..., opts SignOptions) (*Signature, error) {
    // ... existing code ...

    err = signedData.AddSigner(certificate.Certificate, privateKey, signerConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to add signer: %w", err)
    }

    // Handle certificate mode
    switch opts.CertificateMode {
    case CertModeEmbed, "":  // Default or empty = embed
        // AddSigner already included certificate - do nothing

    case CertModeReference:
        // Remove certificate from PKCS#7 (signedData.certs)
        // SignerInfo already contains IssuerAndSerialNumber by default
        // Verifier will look up certificate from store
        signedData.RemoveCertificates()

    case CertModeNone:
        // Remove both certificate and issuer info
        // Advanced use only - must be explicitly documented
        signedData.RemoveCertificates()
        signedData.RemoveSignerIssuerInfo()

    default:
        return nil, fmt.Errorf("unsupported certificate mode: %s", opts.CertificateMode)
    }

    // ... rest of code ...
}
```

#### 1.2 Update Verification Logic (`signing/verifier.go`)

```go
func VerifySignature(data []byte, signature *Signature, opts VerifyOptions) error {
    // ... existing validation ...

    // Extract or look up certificate
    if signature.Certificate == nil {
        p7, err := pkcs7.Parse(signature.Data)
        if err != nil {
            return fmt.Errorf("failed to parse PKCS#7: %w", err)
        }

        if len(p7.Certificates) > 0 {
            // Certificate embedded (CertModeEmbed)
            signature.Certificate = p7.Certificates[0]
        } else if opts.CertificateStore != nil {
            // Certificate reference mode - look up from store
            signer := p7.Signers[0]
            cert, err := opts.CertificateStore.GetCertificate(
                signer.IssuerAndSerialNumber.IssuerName.String(),
                signer.IssuerAndSerialNumber.SerialNumber,
            )
            if err != nil {
                return fmt.Errorf("certificate lookup failed: %w", err)
            }
            signature.Certificate = cert
        } else {
            return fmt.Errorf("no certificate in PKCS#7 and no certificate store provided")
        }
    }

    // ... rest of verification ...
}
```

#### 1.3 Add Certificate Store Interface (`signing/cert_store.go`)

```go
package signing

import (
    "crypto/x509"
    "fmt"
    "math/big"
    "sync"
)

// CertificateStore provides certificate lookup for reference mode signatures
type CertificateStore interface {
    GetCertificate(issuerDN string, serialNumber *big.Int) (*x509.Certificate, error)
}

// MemoryCertificateStore is an in-memory certificate store
type MemoryCertificateStore struct {
    mu    sync.RWMutex
    certs map[string]*x509.Certificate
}

// NewMemoryCertificateStore creates a new in-memory certificate store
func NewMemoryCertificateStore() *MemoryCertificateStore {
    return &MemoryCertificateStore{
        certs: make(map[string]*x509.Certificate),
    }
}

// AddCertificate adds a certificate to the store
func (s *MemoryCertificateStore) AddCertificate(cert *x509.Certificate) {
    s.mu.Lock()
    defer s.mu.Unlock()

    key := certificateKey(cert.Issuer.String(), cert.SerialNumber)
    s.certs[key] = cert
}

// GetCertificate retrieves a certificate by issuer and serial
func (s *MemoryCertificateStore) GetCertificate(issuerDN string, serialNumber *big.Int) (*x509.Certificate, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    key := certificateKey(issuerDN, serialNumber)
    cert, ok := s.certs[key]
    if !ok {
        return nil, ErrCertificateNotFound
    }
    return cert, nil
}

func certificateKey(issuer string, serial *big.Int) string {
    return fmt.Sprintf("%s:%s", issuer, serial.String())
}
```

### Phase 2: Testing (1-2 hours)

#### 2.1 Unit Tests (`signing/signing_test.go`)

```go
func TestCertificateReferenceMode(t *testing.T) {
    // Test signature size with reference mode
    // Verify certificate not embedded in PKCS#7
    // Verify IssuerAndSerialNumber present
}

func TestCertificateStoreVerification(t *testing.T) {
    // Sign with reference mode
    // Verify with certificate store
    // Should succeed
}

func TestCertificateStoreMissing(t *testing.T) {
    // Sign with reference mode
    // Verify without certificate store
    // Should fail with clear error
}

func TestBackwardCompatibility(t *testing.T) {
    // Verify IncludeCertificate still works
    // Should map to CertModeEmbed
}
```

#### 2.2 Compatibility Tests (`compatibility/signing/`)

```go
func TestReferenceModeSize(t *testing.T) {
    // Verify reference mode achieves target size
    // RSA: < 200 bytes
    // ECDSA: < 180 bytes
    // Ed25519: < 150 bytes
}
```

### Phase 3: Documentation (30-60 minutes)

Update documentation:
- `signing/README.md` - API documentation and examples
- `docs/ALGORITHMS.md` - Size comparison table
- `examples/signing/` - Reference mode example

---

## Example Usage

### Signing with Reference Mode

```go
package main

import (
    "github.com/jasoet/gopki/signing"
    "github.com/jasoet/gopki/keypair/algo"
    "github.com/jasoet/gopki/cert"
)

func main() {
    // Generate key and certificate
    keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
    certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
        Subject: pkix.Name{CommonName: "Ticket Issuer"},
        ValidFor: 365 * 24 * time.Hour,
    })

    // Sign with reference mode (minimal size)
    opts := signing.DefaultSignOptions()
    opts.CertificateMode = signing.CertModeReference  // Only issuer+serial
    opts.Detached = true  // Don't embed data

    ticketData := []byte("TICKET-123456")
    signature, _ := signing.SignDocument(ticketData, keyPair, certificate, opts)

    fmt.Printf("Signature size: %d bytes\n", len(signature.Data))  // ~150 bytes

    // Encode for QR code
    qrData := append(ticketData, signature.Data...)
    fmt.Printf("Total QR data: %d bytes\n", len(qrData))  // ~250 bytes
}
```

### Verification with Certificate Store

```go
func VerifyTicket(ticketData, signatureData []byte) error {
    // Create certificate store with trusted issuers
    certStore := signing.NewMemoryCertificateStore()
    certStore.AddCertificate(trustedIssuerCert)  // Pre-loaded trusted certs

    // Verify signature (certificate looked up from store)
    signature := &signing.Signature{
        Data:   signatureData,
        Format: signing.FormatPKCS7Detached,
    }

    opts := signing.DefaultVerifyOptions()
    opts.CertificateStore = certStore  // Provide certificate store

    return signing.VerifySignature(ticketData, signature, opts)
}
```

---

## Security Considerations

### Certificate Reference Mode

**Requirements:**
1. **Trusted Certificate Store**: Verifier MUST have authenticated access to certificate store
2. **Certificate Validation**: Retrieved certificates MUST be validated (expiry, revocation)
3. **Store Security**: Certificate store MUST be protected from tampering
4. **Clear Documentation**: Security implications MUST be documented

**Threat Model:**

| Threat | Mitigation |
|--------|------------|
| **Certificate substitution** | Store must authenticate certificate source |
| **Expired certificate** | Verifier must check certificate validity |
| **Revoked certificate** | Integration with CRL/OCSP recommended |
| **Missing certificate** | Clear error message, fail closed |

**Recommendations:**
- Use `CertModeReference` only in controlled environments (enterprise, ticketing systems)
- Document security requirements clearly
- Provide reference implementation of secure certificate store
- Add security examples to documentation

### Certificate None Mode

**Warning:** `CertModeNone` should be clearly marked as **experimental/advanced use only**. It removes critical security metadata and should only be used when certificate binding is handled through external mechanisms.

---

## Breaking Changes Assessment

**No breaking changes:**
- New `CertificateMode` field has default value (empty string → `CertModeEmbed`)
- Existing `IncludeCertificate` field maintained for backward compatibility
- Default behavior unchanged (embeds certificate)
- Opt-in feature (must explicitly set `CertificateMode = CertModeReference`)

---

## Success Criteria

**Functional:**
- [ ] Reference mode signatures are 75-85% smaller than embed mode
- [ ] Certificate store lookup works correctly
- [ ] Verification succeeds with proper store configuration
- [ ] Verification fails gracefully without store
- [ ] All existing tests pass

**Quality:**
- [ ] 100% test coverage for new code
- [ ] Compatibility tests for all algorithms
- [ ] Security tests for certificate lookup
- [ ] Performance benchmarks showing size reduction

**Documentation:**
- [ ] API documentation complete
- [ ] Security considerations documented
- [ ] Example implementations provided
- [ ] Migration guide (if needed)

---

## Alternative Approaches Considered

### 1. External Certificate Storage (Current Workaround)

**Approach:** Store certificates separately, pass only signature data.

**Pros:**
- No changes to gopki required
- Complete control over certificate management

**Cons:**
- Manual implementation required by every user
- No standardization (different apps do it differently)
- Error-prone (easy to make mistakes)

### 2. URL-Based Certificate References

**Approach:** Include URL to certificate in PKCS#7 custom attribute.

**Pros:**
- More flexible (can fetch from anywhere)
- Standard HTTP infrastructure

**Cons:**
- Network dependency for verification
- Latency and availability issues
- Security complexity (TLS, authentication)
- Not suitable for offline verification

### 3. Certificate Hash Instead of Issuer+Serial

**Approach:** Use SHA-256 hash of certificate as identifier.

**Pros:**
- Fixed size (32 bytes)
- Content-addressed (prevents substitution)

**Cons:**
- Non-standard (not part of PKCS#7 spec)
- Store lookup requires hash index
- Less interoperable with existing tools

**Decision:** Issuer+Serial (proposed solution) is **standard PKCS#7**, already present in SignerInfo, and widely supported by existing tools.

---

## Implementation Checklist

### Code Changes
- [ ] Add `CertificateMode` type and constants to `signing/signing.go`
- [ ] Update `SignOptions` struct with `CertificateMode` field
- [ ] Implement certificate mode handling in `signer.go`
- [ ] Add `CertificateStore` interface to new file `cert_store.go`
- [ ] Implement `MemoryCertificateStore` reference implementation
- [ ] Update `VerifyOptions` with `CertificateStore` field
- [ ] Implement certificate lookup in `verifier.go`
- [ ] Add `ErrCertificateNotFound` error constant

### Testing
- [ ] Unit test: `TestCertificateReferenceMode`
- [ ] Unit test: `TestCertificateStoreVerification`
- [ ] Unit test: `TestCertificateStoreMissing`
- [ ] Unit test: `TestBackwardCompatibility`
- [ ] Unit test: `TestCertificateModeNone`
- [ ] Compatibility test: `TestReferenceModeSize`
- [ ] Security test: `TestCertificateSubstitutionPrevention`
- [ ] Integration test: QR code example with reference mode

### Documentation
- [ ] Update `signing/README.md` with CertificateMode documentation
- [ ] Add security considerations section
- [ ] Create example: `examples/signing/reference_mode/`
- [ ] Update `docs/ALGORITHMS.md` size comparison table
- [ ] Add troubleshooting guide for certificate store issues

### Review
- [ ] Security review by maintainer
- [ ] Performance benchmarks (signature size, speed)
- [ ] Code review
- [ ] Documentation review

---

## Timeline Estimate

| Phase | Tasks | Time |
|-------|-------|------|
| **Phase 1** | Core implementation | 3-4 hours |
| **Phase 2** | Testing | 1-2 hours |
| **Phase 3** | Documentation | 0.5-1 hour |
| **Total** | | **4.5-7 hours** |

---

## References

### Standards
- **RFC 5652**: Cryptographic Message Syntax (CMS) - Section 5.3 (SignerInfo)
- **RFC 2315**: PKCS #7 - Certificate handling
- **ISO/IEC 18004**: QR Code size and error correction

### Related Issues
- Issue #1: Duplicate certificate (✅ Fixed in v1.18.0)
- Issue #2: Certificate extraction (✅ Fixed in v1.18.0)
- Issue #3: Detached flag (✅ Fixed in v1.18.0)

### External Resources
- `smallstep/pkcs7`: SignerInfo structure and IssuerAndSerialNumber
- QR Code capacity tables: Version 7 = ~300 bytes (with error correction)

---

## Questions for Design Review

1. **Certificate Store Interface**: Should we provide multiple implementations (memory, file-based, database)?
2. **Certificate Chain**: How should reference mode handle certificate chains?
3. **CRL/OCSP**: Should certificate store interface include revocation checking?
4. **Backward Compatibility**: Deprecate `IncludeCertificate` field or keep it?
5. **Certificate Mode None**: Include in v1 or defer to future version?

---

**End of Feature Request**

*Created: 2025-10-27*
*Status: Awaiting design review and prioritization*
