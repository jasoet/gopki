# Signing Compatibility Tests

OpenSSL compatibility tests for GoPKI digital signature operations, ensuring 100% interoperability between GoPKI and OpenSSL.

## Quick Start

### Run Signing Compatibility Tests

```bash
# Using Taskfile (recommended)
task test:compatibility:signing

# Direct Go command
go test -tags=compatibility ./compatibility/signing -v

# Run all compatibility tests
go test -tags=compatibility ./compatibility/... -v
```

## Test Coverage

### ✅ **Algorithms Tested**
- **RSA**: 2048, 3072, 4096-bit signatures
- **ECDSA**: P-256, P-384, P-521 curves
- **Ed25519**: Modern high-performance signatures

### ✅ **Signature Formats**
- **Raw Signatures**: Algorithm-specific binary signatures
- **PKCS#7 Attached**: Signature with embedded data
- **PKCS#7 Detached**: Signature separate from data
- **Certificate Chain**: Multi-level certificate inclusion

### ✅ **Bidirectional Testing**
- GoPKI signs → OpenSSL verifies
- OpenSSL signs → GoPKI verifies
- Cross-platform signature validation
- Format interoperability verification

## Requirements

- **OpenSSL 3.0+** (compatible with 1.1.1)
- **Go 1.21+** with module support
- **testify** assertion library

## Sample Output

```
🔐 Running OpenSSL Signing Compatibility Tests...
=== RUN   TestSigningCompatibility/RSA/RSA_2048/Raw_Signature_Compatibility/GoPKI_Sign_OpenSSL_Verify
    → Creating raw RSA signature with OpenSSL...
    ✓ Success: generated 256 bytes of output
    ✓ GoPKI RSA signature verified by OpenSSL
=== RUN   TestSigningCompatibility/RSA/RSA_2048/PKCS7_Signature_Compatibility/GoPKI_PKCS7_OpenSSL_Verify
    → Creating PKCS#7 signature with OpenSSL (detached: false)...
    ✓ Success: generated 1024 bytes of output
    ✓ GoPKI RSA PKCS#7 signature verified by OpenSSL
--- PASS: TestSigningCompatibility/RSA (0.45s)
✅ OpenSSL signing compatibility tests completed
```

## Features

- **Enhanced Logging**: Every OpenSSL command execution is logged
- **Automatic Cleanup**: Temporary files are properly managed
- **Cross-Platform**: Works with OpenSSL 3.x, 1.1.1, LibreSSL
- **Security Validation**: Ensures cryptographic correctness
- **Build Tags**: Conditional testing with `//go:build compatibility`

## Documentation

- **[Complete Documentation](./doc.md)**: Comprehensive signing compatibility guide
- **[Main Compatibility README](../README.md)**: Overview of all compatibility tests
- **[Implementation Details](./doc.md#test-implementation)**: Architecture and usage examples

## Troubleshooting

**OpenSSL Not Found:**
```bash
which openssl
openssl version
```

**Test Failures:**
- Check OpenSSL version compatibility
- Verify temporary directory permissions
- Enable verbose logging with `-v` flag
- Check [troubleshooting guide](./doc.md#troubleshooting)

This framework ensures GoPKI maintains **100% compatibility** with OpenSSL for all digital signature operations and formats.