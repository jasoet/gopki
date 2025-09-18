# OpenSSL Compatibility Framework

This directory contains comprehensive compatibility tests ensuring perfect interoperability between GoPKI and OpenSSL.

## Structure

```
compatibility/
├── keypair/            # Keypair compatibility tests
│   ├── keypair_test.go # RSA, ECDSA, Ed25519 compatibility tests
│   └── doc.md         # Detailed keypair compatibility documentation
├── helpers.go          # OpenSSL integration utilities
├── testdata/           # Test data directory
└── README.md          # This overview
```

## Quick Start

### Run All Compatibility Tests
```bash
# Using Taskfile (recommended)
task test:compatibility

# Direct Go command
go test -mod=mod ./compatibility/... -v
```

### Run Specific Tests
```bash
# Keypair-specific tests only
go test -mod=mod ./compatibility/keypair -v

# Specific algorithm tests
go test -mod=mod ./compatibility/keypair -v -run TestRSAKeypairCompatibility
go test -mod=mod ./compatibility/keypair -v -run TestECDSAKeypairCompatibility
go test -mod=mod ./compatibility/keypair -v -run TestEd25519KeypairCompatibility
```

## Test Coverage

### ✅ **Keypair Compatibility** (`./keypair/`)
- **RSA**: 2048, 3072, 4096-bit keys
- **ECDSA**: P-256, P-384, P-521 curves
- **Ed25519**: Modern high-performance curve
- **Bidirectional testing**: GoPKI ↔ OpenSSL
- **Format validation**: PEM, DER, SSH
- **Signature interoperability**: Cross-platform verification

### 🔮 **Future Compatibility Tests**
As GoPKI grows, additional compatibility tests will be organized here:
- `./cert/` - Certificate compatibility with OpenSSL
- `./signing/` - PKCS#7/CMS signature compatibility
- `./encryption/` - Encryption/decryption compatibility

## Features

- **Enhanced Logging**: Every OpenSSL command execution is logged with results
- **Testify Assertions**: Clean, readable test assertions
- **Automatic Cleanup**: Temporary files are properly managed
- **Cross-Platform**: Works with OpenSSL 3.x, 1.1.1, LibreSSL
- **Security Validation**: Ensures cryptographic correctness

## Sample Output

```
🔗 Running OpenSSL Compatibility Tests...
   This tests interoperability between GoPKI and OpenSSL

=== RUN   TestRSAKeypairCompatibility/RSA_2048/GoPKI_Generate_OpenSSL_Validate
    → Validating RSA private key with OpenSSL...
    → Executing: openssl rsa -in /tmp/private_key.pem -check -noout
    ✓ Success: RSA key ok
    ✓ RSA private key validation passed
    ✓ GoPKI RSA-2048 key validated by OpenSSL

--- PASS: TestRSAKeypairCompatibility (2.87s)
    --- PASS: TestRSAKeypairCompatibility/RSA_2048 (0.22s)
✅ OpenSSL compatibility tests completed
```

## Documentation

- **Detailed Guide**: See [`./keypair/doc.md`](./keypair/doc.md) for comprehensive keypair compatibility documentation
- **Implementation Details**: Architecture, usage examples, and troubleshooting
- **Standards Compliance**: RFC references and OpenSSL command documentation

This framework ensures GoPKI maintains **100% compatibility** with OpenSSL operations.