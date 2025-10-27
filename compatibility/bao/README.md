# OpenBao Compatibility Tests

This directory contains compatibility tests that verify seamless interoperability between **GoPKI local modules** and the **OpenBao client** (via the `bao` package).

## Overview

These tests ensure that cryptographic materials (keys, certificates, signatures) created by one system work correctly with the other:

- ✅ **GoPKI → OpenBao**: Keys/certificates generated locally can be imported and used with OpenBao
- ✅ **OpenBao → GoPKI**: Materials from OpenBao work with local GoPKI operations
- ✅ **Bidirectional**: Full round-trip compatibility for all operations

## Test Coverage

### 1. **Keypair Compatibility** (`keypair_test.go`)
Tests that keys work bidirectionally between GoPKI and OpenBao:
- RSA keys (2048, 3072, 4096 bits)
- ECDSA keys (P-256, P-384, P-521)
- Ed25519 keys
- Key import/export workflows
- Certificate issuance with imported keys

### 2. **Certificate Compatibility** (`cert_test.go`)
Tests certificate operations and workflows:
- CSR creation with GoPKI → signing with OpenBao
- Root CA and intermediate CA creation
- Certificate chain validation
- All 4 certificate issuance workflows
- Subject/SAN preservation
- Extension handling

### 3. **Signing Compatibility** (`signing_test.go`)
Tests that OpenBao-issued certificates work with GoPKI signing:
- PKCS#7 signatures with all key types
- Detached signatures
- Certificate chain inclusion
- Signature verification

### 4. **Encryption Compatibility** (`encryption_test.go`)
Tests encryption operations with OpenBao materials:
- RSA-OAEP encryption/decryption
- ECDH key agreement
- Certificate-based encryption
- Mixed key sources

### 5. **PKCS#12 Compatibility** (`pkcs12_test.go`)
Tests PKCS#12 bundle operations:
- Creating bundles from OpenBao certificates
- Including certificate chains
- Parsing and re-importing
- Full export workflows

### 6. **JOSE Compatibility** (`jose_test.go`)
Tests JOSE operations with OpenBao keys:
- JWK export/import
- JWS signing (RS256, ES256, EdDSA)
- JWT creation and verification
- Claims validation

### 7. **End-to-End Workflows** (`workflow_test.go`)
Real-world integration scenarios:
- Web server certificate deployment
- Code signing workflow
- Email protection (S/MIME)
- Mutual TLS setup
- Certificate renewal

## Running the Tests

### Run All OpenBao Compatibility Tests

```bash
# Using Taskfile
task test:compatibility:bao

# Or directly with go test
go test -tags=compatibility ./compatibility/bao -v
```

### Run Specific Test Suites

```bash
# Keypair tests only
go test -tags=compatibility ./compatibility/bao -v -run TestKeypair

# Certificate tests only
go test -tags=compatibility ./compatibility/bao -v -run TestCert

# Workflow tests only
go test -tags=compatibility ./compatibility/bao -v -run TestE2E
```

### Run with Race Detection

```bash
go test -tags=compatibility ./compatibility/bao -v -race
```

## Prerequisites

- **Docker**: Tests use testcontainers to run OpenBao
- **Go 1.21+**: Required for running tests
- **Network access**: Docker needs to pull OpenBao image

## How Tests Work

1. **Test Container Setup**: Each test starts an OpenBao container using `testcontainer.Start()`
2. **PKI Engine**: Automatically enables the PKI secrets engine
3. **Test Execution**: Runs compatibility checks
4. **Cleanup**: Container is automatically terminated after tests

Example:
```go
func TestExample(t *testing.T) {
    env := SetupBaoTest(t)
    defer env.Cleanup()

    // env.Client is ready to use
    // env.Ctx is the context
    // Tests run here...
}
```

## Test Patterns

### Pattern 1: GoPKI Generate → Bao Import
```go
keyPair, _ := algo.GenerateRSAKeyPair(2048)
keyClient, _ := env.Client.ImportRSAKey(ctx, "my-key", keyPair, &bao.ImportKeyOptions{})
```

### Pattern 2: Bao Generate → GoPKI Use
```go
keyClient, _ := env.Client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{...})
keyPair, _ := keyClient.KeyPair()
csr, _ := cert.CreateCSR(keyPair, csrReq) // Use with GoPKI
```

### Pattern 3: Bao CA → GoPKI Sign
```go
issuer, _ := env.Client.GenerateRootCA(ctx, &bao.CAOptions{...})
csr, _ := cert.CreateCSR(keyPair, csrReq)
certificate, _ := issuer.SignCSR(ctx, "role", csr, &bao.SignCertificateOptions{})
```

## Success Criteria

All tests verify:

✅ **Type Safety**: Generic type parameters work correctly
✅ **Standards Compliance**: RFC 5280, 5652 compliance
✅ **Format Compatibility**: PEM, DER, PKCS#7, PKCS#12
✅ **Chain Validation**: Multi-level certificate chains
✅ **Extension Preservation**: Key usage, EKU, SANs
✅ **Algorithm Support**: RSA, ECDSA, Ed25519

## Troubleshooting

### Container Fails to Start
```bash
# Check Docker is running
docker ps

# Pull OpenBao image manually
docker pull openbao/openbao:2.4.3
```

### Tests Timeout
```bash
# Increase timeout
go test -tags=compatibility ./compatibility/bao -v -timeout 10m
```

### Port Conflicts
Tests use random ports via testcontainers, so port conflicts should be rare. If issues persist, ensure no other OpenBao instances are running.

## Related Documentation

- [Bao Package Documentation](../../bao/README.md)
- [OpenBao Documentation](https://openbao.org/docs/)
- [GoPKI Main README](../../README.md)
- [Other Compatibility Tests](../README.md)

## Contributing

When adding new tests:

1. Follow existing naming conventions
2. Use helper functions from `helpers.go`
3. Always call `defer env.Cleanup()`
4. Add descriptive log messages
5. Test both directions (GoPKI ↔ OpenBao)
