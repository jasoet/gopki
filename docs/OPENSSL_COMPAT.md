# OpenSSL Compatibility Guide

**Complete guide to OpenSSL integration and interoperability with GoPKI.**

## Overview

GoPKI achieves **95%+ compatibility** with OpenSSL and OpenSSH, enabling seamless integration with existing cryptographic infrastructure. This guide provides practical patterns for bidirectional interoperability.

## Compatibility Summary

| Feature | Compatibility | Notes |
|---------|--------------|-------|
| **Certificates** | ✅ 100% | All algorithms, full bidirectional |
| **SSH Keys** | ✅ 100% | OpenSSH format, all algorithms |
| **Raw Signatures** | ✅ 100% | All algorithms bidirectional |
| **PKCS#7 Signatures** | ✅ 95% | Ed25519 has OpenSSL limitations |
| **Key Agreement** | ✅ 100% | ECDH, X25519 full compatibility |
| **Envelope Encryption** | ✅ 100% RSA | ECDSA/Ed25519 GoPKI-only |
| **RSA-OAEP** | ⚠️ Limited | Parameter differences |

## Envelope Encryption (SMIME)

### OpenSSL Encrypts → GoPKI Decrypts

**Complete Example:**

```bash
# 1. Create certificate with OpenSSL or GoPKI
# Using GoPKI:
go run examples/certificates/main.go

# 2. OpenSSL encrypts data
openssl smime -encrypt -aes256 -binary \
    -in plaintext.txt \
    -out encrypted.p7 \
    certificate.pem

# Output: encrypted.p7 (PKCS#7 EnvelopedData format)
```

```go
// 3. GoPKI decrypts
package main

import (
    "os"
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Load key pair (used to create certificate)
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)  // Or load existing

    // Load certificate
    certificate, _ := cert.LoadCertificateFromFile("certificate.pem")

    // Read OpenSSL encrypted data
    cmsData, _ := os.ReadFile("encrypted.p7")

    // GoPKI auto-detects OpenSSL format and decrypts
    decoded, _ := encryption.DecodeDataWithKey(cmsData, certificate.Certificate, keyPair.PrivateKey)

    // decoded.Data contains the plaintext!
    os.WriteFile("decrypted.txt", decoded.Data, 0644)

    // ✅ Success! GoPKI decrypted OpenSSL smime data
}
```

**Key Points:**
- ✅ GoPKI **auto-detects** OpenSSL PKCS#7 EnvelopedData format
- ✅ `DecodeDataWithKey()` handles both GoPKI and OpenSSL formats
- ✅ Plaintext is in `decoded.Data` (already decrypted)
- ✅ Works with OpenSSL smime command

### GoPKI Encrypts → OpenSSL Decrypts

**Complete Example:**

```go
// 1. GoPKI encrypts with OpenSSL-compatible mode
package main

import (
    "os"
    "github.com/jasoet/gopki/encryption"
    "github.com/jasoet/gopki/encryption/envelope"
    "github.com/jasoet/gopki/cert"
    "github.com/jasoet/gopki/keypair/algo"
)

func main() {
    // Generate RSA key pair (required for OpenSSL smime)
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // Create certificate
    certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{...})

    // Save certificate for OpenSSL
    certificate.SaveToFile("certificate.pem")

    // Plaintext data
    data := []byte("Secret message for OpenSSL")

    // Enable OpenSSL-compatible mode
    opts := encryption.DefaultEncryptOptions()
    opts.OpenSSLCompatible = true  // ← CRITICAL: Enable OpenSSL mode

    // Encrypt with envelope
    encrypted, _ := envelope.EncryptWithCertificate(data, certificate, opts)

    // Encode to CMS format
    cmsData, _ := encryption.EncodeToCMS(encrypted)

    // Save for OpenSSL
    os.WriteFile("encrypted.p7", cmsData, 0644)

    // ✅ Success! OpenSSL can now decrypt this
}
```

```bash
# 2. OpenSSL decrypts
openssl smime -decrypt \
    -in encrypted.p7 \
    -inkey private.pem \
    -out decrypted.txt

# ✅ Success! OpenSSL decrypted GoPKI data
```

**Key Points:**
- ⚠️ **RSA certificates only** - OpenSSL smime doesn't support ECDSA/Ed25519 envelope
- ✅ Set `opts.OpenSSLCompatible = true` for GoPKI → OpenSSL workflow
- ✅ Creates standard PKCS#7 EnvelopedData format
- ✅ Uses AES-256-CBC (OpenSSL standard)

### Envelope Encryption Limitations

| Algorithm | OpenSSL smime Support | GoPKI Support | Workaround |
|-----------|----------------------|---------------|------------|
| **RSA** | ✅ Full | ✅ Full | None needed |
| **ECDSA** | ❌ Not supported | ✅ Full | Use RSA for OpenSSL compat |
| **Ed25519** | ❌ Not supported | ✅ Full | Use RSA for OpenSSL compat |

**Why the Limitation?**
- OpenSSL `smime` command only supports RSA for envelope encryption
- This is an OpenSSL limitation, not a GoPKI limitation
- ECDSA and Ed25519 envelope encryption work perfectly within GoPKI

## Certificate Management

### Creating OpenSSL-Compatible Certificates

```go
// GoPKI creates certificate
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
    Subject: pkix.Name{CommonName: "example.com"},
    DNSNames: []string{"example.com", "www.example.com"},
    ValidFor: 365 * 24 * time.Hour,
})

// Save in PEM format
certificate.SaveToFile("certificate.pem")
```

```bash
# OpenSSL verifies certificate
openssl x509 -in certificate.pem -text -noout

# ✅ Shows certificate details
# ✅ Verifies signature
# ✅ Shows SANs
```

### Verifying OpenSSL Certificates with GoPKI

```bash
# OpenSSL creates certificate
openssl req -x509 -newkey rsa:2048 -keyout private.pem -out certificate.pem -days 365 -nodes
```

```go
// GoPKI loads and verifies
certificate, _ := cert.LoadCertificateFromFile("certificate.pem")

// Verify certificate
_ = cert.VerifyCertificate(certificate, caCert)  // ✅ Works!
```

## Digital Signatures

### Raw Signatures (100% Compatible)

**All algorithms fully bidirectional:**

```go
// GoPKI signs
keyPair, _ := algo.GenerateEd25519KeyPair()
signature := ed25519.Sign(keyPair.PrivateKey, message)

// Save signature and public key for OpenSSL
os.WriteFile("signature.bin", signature, 0644)
publicPEM, _ := keypair.PublicKeyToPEM(keyPair.PublicKey)
os.WriteFile("public.pem", publicPEM, 0644)
```

```bash
# OpenSSL verifies
openssl pkeyutl -verify \
    -pubin -inkey public.pem \
    -sigfile signature.bin \
    -in message.txt

# ✅ Verification successful
```

### PKCS#7 Signatures

**RSA and ECDSA: 100% Compatible**

```go
// GoPKI creates PKCS#7 signature
rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
certificate, _ := cert.CreateSelfSignedCertificate(rsaKeys, ...)
pkcs7Data, _ := signing.CreatePKCS7Signature(document, rsaKeys, certificate, true)

os.WriteFile("signature.p7s", pkcs7Data, 0644)
```

```bash
# OpenSSL verifies PKCS#7 signature
openssl smime -verify \
    -in signature.p7s \
    -CAfile ca_cert.pem \
    -out verified.txt

# ✅ Verification successful
```

**Ed25519: Limited OpenSSL Support**

```go
// GoPKI creates Ed25519 PKCS#7 signature
ed25519Keys, _ := algo.GenerateEd25519KeyPair()
certificate, _ := cert.CreateSelfSignedCertificate(ed25519Keys, ...)
pkcs7Data, _ := signing.CreatePKCS7Signature(document, ed25519Keys, certificate, true)

// ✅ GoPKI creates valid PKCS#7 signature
// ⚠️ OpenSSL may not verify (OpenSSL limitation, not GoPKI)
```

**Workaround for Ed25519:**
- Use raw signatures for OpenSSL compatibility
- Or use RSA/ECDSA for PKCS#7 signatures

## SSH Key Management

### GoPKI → OpenSSH (100% Compatible)

```go
// GoPKI generates SSH key
manager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)

// Save as SSH format
manager.SaveToSSH("~/.ssh/id_ed25519", "~/.ssh/id_ed25519.pub", "user@host", "")
```

```bash
# ssh-keygen verifies
ssh-keygen -l -f ~/.ssh/id_ed25519.pub

# ✅ Shows fingerprint
# ✅ Shows key type (Ed25519)
# ✅ Shows comment

# Use with SSH
ssh -i ~/.ssh/id_ed25519 user@server
# ✅ Works perfectly!
```

### OpenSSH → GoPKI (100% Compatible)

```bash
# Generate SSH key with ssh-keygen
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "user@host"
```

```go
// GoPKI loads SSH key
manager, _ := keypair.LoadFromSSH[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("~/.ssh/id_ed25519", "")

// ✅ Loaded successfully
// Use for signing, encryption, etc.
```

## Key Agreement (ECDH, X25519)

### 100% Compatible

```go
// GoPKI performs ECDH
ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)

// Export public key for OpenSSL
publicPEM, _ := keypair.PublicKeyToPEM(ecdsaKeys.PublicKey)
os.WriteFile("ecdsa_public.pem", publicPEM, 0644)
```

```bash
# OpenSSL performs ECDH with GoPKI public key
openssl pkeyutl -derive \
    -inkey openssl_private.pem \
    -peerkey ecdsa_public.pem \
    -out shared_secret.bin

# ✅ Same shared secret as GoPKI!
```

**Verified Compatible:**
- ✅ ECDH P-256, P-384, P-521
- ✅ X25519 key agreement
- ✅ Bidirectional (GoPKI ↔ OpenSSL)

## RSA-OAEP Encryption

### Limited Compatibility (Parameter Differences)

**Issue**: GoPKI and OpenSSL use different OAEP parameters by default

**Status**:
- ✅ Both systems work internally
- ⚠️ Cross-compatibility limited
- ⚠️ Not recommended for GoPKI ↔ OpenSSL workflows

**Recommendation**: Use envelope encryption or ECDH + AES-GCM instead

```go
// Instead of RSA-OAEP for OpenSSL compatibility:
// Use envelope encryption with OpenSSL-compatible mode

opts := encryption.DefaultEncryptOptions()
opts.OpenSSLCompatible = true
encrypted, _ := envelope.EncryptWithCertificate(data, certificate, opts)
```

## Testing OpenSSL Compatibility

### Running Compatibility Tests

```bash
# Full compatibility test suite
task test:compatibility

# Or manually:
go test -tags=compatibility ./compatibility/...

# Specific OpenSSL tests
go test -tags=compatibility ./compatibility/encryption/... -v
go test -tags=compatibility ./compatibility/keypair/... -v
```

### Adding New OpenSSL Compatibility Test

```go
//go:build compatibility

package encryption

import (
    "testing"
    "github.com/jasoet/gopki/compatibility"
)

func TestNewOpenSSLFeature(t *testing.T) {
    helper := compatibility.NewOpenSSLHelper(t)
    defer helper.Cleanup()

    // 1. GoPKI operation
    encrypted, _ := gopkiEncrypt(data)

    // 2. Save for OpenSSL
    helper.WriteFile("encrypted.bin", encrypted)

    // 3. OpenSSL operation
    output, _ := helper.RunOpenSSL("enc", "-d", "-aes-256-gcm", "-in", "encrypted.bin")

    // 4. Verify
    assert.Equal(t, originalData, output)
}
```

## Troubleshooting

### Issue: OpenSSL can't decrypt GoPKI envelope

**Symptom**: `openssl smime -decrypt` fails with GoPKI-encrypted data

**Solution**:
```go
// Enable OpenSSL-compatible mode
opts := encryption.DefaultEncryptOptions()
opts.OpenSSLCompatible = true  // ← Add this
encrypted, _ := envelope.EncryptWithCertificate(data, certificate, opts)
```

### Issue: GoPKI can't decrypt OpenSSL envelope

**Symptom**: Decryption fails with OpenSSL-encrypted data

**Solution**: Use `DecodeDataWithKey()` which auto-detects format
```go
// This works with both GoPKI and OpenSSL formats
decoded, _ := encryption.DecodeDataWithKey(cmsData, certificate, privateKey)
plaintext := decoded.Data  // Already decrypted
```

### Issue: Ed25519 PKCS#7 signature verification fails in OpenSSL

**Symptom**: OpenSSL can't verify Ed25519 PKCS#7 signatures

**Explanation**: This is an **OpenSSL limitation**, not a GoPKI issue

**Solution**: Use raw Ed25519 signatures for OpenSSL compatibility
```go
// Instead of PKCS#7:
signature := ed25519.Sign(privateKey, message)

// OpenSSL can verify raw Ed25519 signatures
```

### Issue: ECDSA envelope encryption with OpenSSL smime

**Symptom**: OpenSSL smime doesn't support ECDSA envelope

**Explanation**: OpenSSL `smime` command only supports RSA

**Solution**: Use RSA for OpenSSL smime compatibility
```go
// For OpenSSL smime compatibility:
rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

// ECDSA works within GoPKI (no OpenSSL needed):
ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
```

## Best Practices

1. **Use OpenSSL-Compatible Mode When Needed**: Set `opts.OpenSSLCompatible = true`
2. **Test Bidirectionally**: Test both GoPKI → OpenSSL and OpenSSL → GoPKI
3. **RSA for SMIME**: Use RSA certificates for OpenSSL smime compatibility
4. **Auto-Detection Works**: `DecodeDataWithKey()` handles both formats
5. **Run Compatibility Tests**: Use `task test:compatibility` before release
6. **Document Limitations**: Ed25519 PKCS#7, OpenSSL smime ECDSA limitations
7. **Prefer Envelope Encryption**: Best for large data and OpenSSL compat

## Compatibility Matrix

### Full Compatibility (100%)

| Feature | GoPKI → OpenSSL | OpenSSL → GoPKI |
|---------|----------------|----------------|
| **Certificates (all algorithms)** | ✅ | ✅ |
| **SSH Keys (all algorithms)** | ✅ | ✅ |
| **Raw Signatures (all)** | ✅ | ✅ |
| **PKCS#7 RSA** | ✅ | ✅ |
| **PKCS#7 ECDSA** | ✅ | ✅ |
| **ECDH Key Agreement** | ✅ | ✅ |
| **X25519 Key Agreement** | ✅ | ✅ |
| **Envelope RSA** | ✅ | ✅ |

### Limited Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| **Ed25519 PKCS#7** | ⚠️ | OpenSSL limitation |
| **RSA-OAEP** | ⚠️ | Parameter differences |
| **Envelope ECDSA/Ed25519** | ❌ | OpenSSL smime doesn't support |

## Further Reading

- **Compatibility Report**: [`COMPATIBILITY_REPORT.md`](COMPATIBILITY_REPORT.md) - Detailed test results
- **Architecture**: [`ARCHITECTURE.md`](ARCHITECTURE.md) - System design
- **Algorithms**: [`ALGORITHMS.md`](ALGORITHMS.md) - Algorithm selection guide
- **Examples**: [`examples/encryption/doc.md`](../examples/encryption/doc.md) - Working examples

---

**Summary**: GoPKI achieves 95%+ OpenSSL compatibility with full bidirectional support for certificates, SSH keys, signatures, and envelope encryption (RSA). The few limitations are well-understood OpenSSL constraints, not GoPKI issues.