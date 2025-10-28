# OpenBao Compatibility Tests

This directory contains compatibility tests that verify seamless interoperability between **GoPKI local modules** and the **OpenBao PKI engine** (via the `bao` package).

## Overview

These tests ensure that cryptographic materials (keys, certificates) created by one system work correctly with the other:

- ✅ **GoPKI → OpenBao**: Keys/certificates generated locally can be imported and used with OpenBao
- ✅ **OpenBao → GoPKI**: Materials from OpenBao work with local GoPKI operations
- ✅ **Bidirectional**: Full round-trip compatibility for all operations

## Test Status

**Achievement: 100% of applicable OpenBao PKI engine compatibility tests are passing! 🎉**

All tests verify interoperability with OpenBao's **PKI engine** specifically. Features not part of the PKI engine (JOSE, PKCS#12, document signing) are intentionally excluded as they belong to other OpenBao engines (Transit) or are application-level concerns.

## Test Coverage

### 1. **Keypair Compatibility** (`keypair_test.go`) ✅

Tests that keys work bidirectionally between GoPKI and OpenBao:

**Key Types:**
- RSA keys (2048, 3072, 4096 bits)
- ECDSA keys (P-256, P-384, P-521)
- Ed25519 keys

**Test Scenarios per Key Type:**
- **GoPKI_Generate_Bao_Import**: Generate with GoPKI → Import to OpenBao → Verify
- **Bao_Generate_GoPKI_Use**: Generate in OpenBao → Export → Use with GoPKI
- **Bao_Issue_Cert_With_GoPKI_Key**: GoPKI key → OpenBao issues certificate → Verify

**Status:** All 21 tests passing (7 key types × 3 scenarios each)

### 2. **Certificate Compatibility** (`cert_test.go`) ✅

Tests certificate operations and workflows:

**CSR Workflows:**
- GoPKI CSR creation → OpenBao signing
- Extension preservation in signed certificates
- Subject information preservation

**CA Operations:**
- Root CA creation and verification
- Intermediate CA chain creation
- Multi-level certificate chain validation
- CA certificate verification with GoPKI

**Certificate Validation:**
- OpenBao certificates parsed with GoPKI
- Certificate chain validation
- Certificate verification against CA

**Certificate Workflows:**
- Workflow 1: OpenBao generates everything (key + cert)
- Workflow 2: Local key, OpenBao signs
- Workflow 3: OpenBao managed key
- Workflow 4: Sign CSR workflow

**Status:** All 15 tests passing

### 3. **Encryption Compatibility** (`encryption_test.go`) ✅

Tests encryption operations with OpenBao materials:

**Supported:**
- RSA-OAEP encryption/decryption with OpenBao-managed keys
- GoPKI key → OpenBao issues certificate → Encrypt with GoPKI

**Not Yet Implemented (Skipped):**
- ECDH key agreement (marked for future implementation)
- Certificate-based encryption API

**Status:** 2 tests passing, 3 tests skipped (not yet implemented)

### 4. **End-to-End Workflows** (`workflow_test.go`) ✅

Real-world integration scenarios combining GoPKI and OpenBao:

**Complete_CA_To_Certificate_Workflow:**
1. Generate Root CA with OpenBao
2. Configure role for certificate issuance
3. Generate key in OpenBao
4. Issue certificate with OpenBao-managed key
5. Verify certificate properties with GoPKI
6. Verify certificate chain with GoPKI
7. Revoke certificate

**Key_Rotation_Workflow:**
1. Generate first key and issue certificate
2. Rotate to second key
3. Issue new certificate with rotated key
4. Verify different serial numbers (rotation successful)
5. Revoke old certificate
6. Verify new certificate still valid

**Hybrid_GoPKI_Bao_Workflow:**
1. Generate key locally with GoPKI
2. Create CSR with GoPKI
3. Sign CSR with OpenBao
4. Verify certificate with GoPKI
5. Import GoPKI key to OpenBao
6. Issue another certificate with imported key
7. Verify final certificate with GoPKI

**Status:** All 3 workflow tests passing

## What's Not Included (By Design)

The following are **NOT** tested as they are not part of OpenBao's PKI engine:

- ❌ **JOSE (JWK/JWS/JWT)**: Handled by OpenBao's Transit engine or JWT/OIDC auth backends
- ❌ **PKCS#12 Bundling**: Application-level concern; PKI engine issues PEM-encoded certificates
- ❌ **Document Signing (PKCS#7/CMS)**: Application-level or Transit engine functionality

These tests focus exclusively on **PKI engine features**: CA management, certificate issuance, and cryptographic key operations.

## Running the Tests

### Run All OpenBao Compatibility Tests

```bash
# Using Taskfile (recommended)
task test:compatibility:bao

# Or directly with go test
go test -tags=compatibility ./compatibility/bao -v
```

### Run Specific Test Suites

```bash
# Keypair tests only
go test -tags=compatibility ./compatibility/bao -run TestKeypair -v

# Certificate tests only
go test -tags=compatibility ./compatibility/bao -run TestCert -v

# Encryption tests only
go test -tags=compatibility ./compatibility/bao -run TestEncryption -v

# Workflow tests only
go test -tags=compatibility ./compatibility/bao -run TestWorkflow -v
```

### Run with Race Detection

```bash
go test -tags=compatibility ./compatibility/bao -race -v
```

## Prerequisites

- **Docker**: Tests use testcontainers to run OpenBao
- **Go 1.21+**: Required for running tests
- **Network access**: Docker needs to pull OpenBao image (`openbao/openbao:2.4.3`)

## How Tests Work

1. **Test Container Setup**: Each test starts an isolated OpenBao container
2. **PKI Engine**: Automatically enables and configures the PKI secrets engine
3. **Test Execution**: Runs compatibility checks between GoPKI and OpenBao
4. **Automatic Cleanup**: Container is terminated after tests complete

### Test Helper Example

```go
func TestExample(t *testing.T) {
    env := SetupBaoTest(t)
    defer env.Cleanup()

    // env.Client is ready to use (OpenBao client)
    // env.Ctx is the context
    // Tests run here...
}
```

### Helper with CA Example

```go
func TestWithCA(t *testing.T) {
    env, issuer := SetupBaoWithCA(t)
    defer env.Cleanup()

    // env.Client - OpenBao client
    // issuer - Pre-configured root CA issuer
    // Tests run here...
}
```

## Test Patterns

### Pattern 1: GoPKI Generate → Bao Import

```go
// Generate key with GoPKI
keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)

// Import to OpenBao
keyClient, err := env.Client.ImportRSAKey(env.Ctx, keyPair, &bao.ImportKeyOptions{
    KeyName: "my-imported-key",
})

// Verify key info
keyInfo := keyClient.KeyInfo()
```

### Pattern 2: Bao Generate → GoPKI Use

```go
// Generate key in OpenBao
keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
    KeyName: "my-bao-key",
    KeyBits: 2048,
})

// Export for use with GoPKI
keyPair, err := keyClient.KeyPair()

// Create CSR with GoPKI
csr, err := cert.CreateCSR(keyPair, csrReq)
```

### Pattern 3: GoPKI CSR → Bao Sign

```go
// Create CSR with GoPKI
keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{
    Subject: pkix.Name{CommonName: "example.com"},
})

// Sign with OpenBao
certificate, err := issuer.SignCSR(env.Ctx, csr, &bao.SignCertificateOptions{
    CommonName: "example.com",
    TTL:        "720h",
})

// Verify with GoPKI
rootCert, _ := issuer.Certificate()
err = cert.VerifyCertificate(certificate, rootCert)
```

### Pattern 4: Complete Workflow

```go
// 1. Create CA with OpenBao
caResp, _ := env.Client.GenerateRootCA(env.Ctx, &bao.CAOptions{
    CommonName: "Root CA",
    KeyType:    "rsa",
    KeyBits:    2048,
})

// 2. Get issuer
issuer, _ := env.Client.GetIssuer(env.Ctx, caResp.IssuerID)

// 3. Create role
issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
    AllowedDomains: []string{"example.com"},
})

// 4. Issue certificate
certClient, _ := env.Client.GenerateRSACertificate(env.Ctx, "web-server",
    &bao.GenerateCertificateOptions{
        CommonName: "app.example.com",
    })

// 5. Verify with GoPKI
certificate := certClient.Certificate()
rootCert, _ := issuer.Certificate()
cert.VerifyCertificate(certificate, rootCert)
```

## Success Criteria

All tests verify:

✅ **Type Safety**: Generic type parameters work correctly across boundaries
✅ **Standards Compliance**: RFC 5280 (X.509), RFC 5652 (CMS) compliance
✅ **Format Compatibility**: PEM, DER encoding/decoding
✅ **Chain Validation**: Multi-level certificate chains (Root → Intermediate → End-entity)
✅ **Extension Preservation**: Key usage, Extended Key Usage, Subject Alternative Names
✅ **Algorithm Support**: RSA (2048/3072/4096), ECDSA (P256/P384/P521), Ed25519
✅ **Bidirectional Operations**: GoPKI ↔ OpenBao compatibility in both directions

## Test Results Summary

```
✅ Keypair Tests:        21/21 passing (100%)
✅ Certificate Tests:    15/15 passing (100%)
✅ Encryption Tests:      2/2 passing (100%, 3 skipped - not yet implemented)
✅ Workflow Tests:        3/3 passing (100%)

Total: 41/41 applicable tests passing
```

## Troubleshooting

### Container Fails to Start

```bash
# Check Docker is running
docker ps

# Pull OpenBao image manually
docker pull openbao/openbao:2.4.3

# Check Docker logs
docker logs <container-id>
```

### Tests Timeout

```bash
# Increase timeout
go test -tags=compatibility ./compatibility/bao -v -timeout 10m

# Run specific test with longer timeout
go test -tags=compatibility ./compatibility/bao -run TestWorkflow -v -timeout 5m
```

### Port Conflicts

Tests use random ports via testcontainers to avoid conflicts. If issues persist:

```bash
# Check for running OpenBao containers
docker ps | grep openbao

# Stop any stray containers
docker stop $(docker ps -q --filter ancestor=openbao/openbao:2.4.3)
```

### Debug Mode

Enable verbose testcontainer logging:

```bash
export TESTCONTAINERS_RYUK_DISABLED=false
go test -tags=compatibility ./compatibility/bao -v
```

## Project Structure

```
compatibility/bao/
├── README.md              # This file
├── helpers_test.go        # Test infrastructure and helpers
├── keypair_test.go        # RSA, ECDSA, Ed25519 key compatibility tests
├── cert_test.go           # Certificate operations and workflows
├── encryption_test.go     # RSA-OAEP encryption tests
└── workflow_test.go       # End-to-end integration workflows
```

## Related Documentation

- [Bao Package Documentation](../../bao/README.md) - OpenBao client implementation
- [OpenBao Documentation](https://openbao.org/docs/) - Official OpenBao docs
- [GoPKI Main README](../../README.md) - Overall project documentation
- [Integration Tests](../../bao/cross_module_integration_test.go) - Full integration test examples

## Contributing

When adding new tests:

1. **Follow Naming Conventions**: Use descriptive test names with `Test<Component>_Bao_Compatibility` pattern
2. **Use Helper Functions**: Leverage `SetupBaoTest()` and `SetupBaoWithCA()` from `helpers_test.go`
3. **Always Cleanup**: Use `defer env.Cleanup()` to ensure container cleanup
4. **Add Logging**: Include descriptive log messages with `t.Log()` for workflow steps
5. **Test Both Directions**: Verify GoPKI → OpenBao AND OpenBao → GoPKI compatibility
6. **Document Skipped Tests**: If a test is skipped, clearly explain why with `t.Skip()`
7. **Focus on PKI Engine**: Only test features supported by OpenBao's PKI secrets engine

### Example Test Structure

```go
func testMyNewFeature(t *testing.T) {
    env, issuer := SetupBaoWithCA(t)
    defer env.Cleanup()

    t.Log("Step 1: Description...")
    // Test step 1

    t.Log("Step 2: Description...")
    // Test step 2

    t.Log("✓ Test completed successfully")
}
```

## License

See [LICENSE](../../LICENSE) in the repository root.
