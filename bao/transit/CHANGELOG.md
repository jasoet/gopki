# Changelog

All notable changes to the OpenBao Transit Client Library will be documented in this file.

## [1.0.0] - 2025-10-28

### Added - Complete Implementation

#### Phase 1: Core Infrastructure
- Client initialization with flexible configuration
- Automatic connection management and pooling
- Comprehensive error handling with typed errors
- Context-based operation cancellation
- Thread-safe operations
- Graceful client shutdown

#### Phase 2: Key Management
- **Key Creation**
  - AES-128-GCM96 and AES-256-GCM96 symmetric keys
  - ChaCha20-Poly1305 symmetric keys
  - RSA-2048, RSA-3072, RSA-4096 asymmetric keys
  - ECDSA P-256, P-384, P-521 keys
  - Ed25519 keys
  - HMAC keys for authentication
- **Key Lifecycle**
  - Key rotation with version tracking
  - Key update (configuration changes)
  - Key deletion with safety controls
  - Key trimming to remove old versions
- **Key Import/Export (BYOK)**
  - Import your own key material
  - Export keys in multiple formats
  - Two-layer wrapping (KWP + RSA-OAEP)
  - Wrapping key retrieval
- **Backup & Restore**
  - Key backup to encrypted format
  - Key restore from backup
  - Cross-instance key migration
- **Type Safety**
  - Generic KeyClient[T] with compile-time safety
  - Type-safe key retrieval methods

#### Phase 3: Encryption & Decryption
- **Single Operations**
  - Encrypt plaintext with symmetric keys
  - Decrypt ciphertext
  - Re-encryption for key rotation (no plaintext exposure)
- **Batch Operations**
  - Encrypt/decrypt up to 1000 items per call
  - Automatic chunking for large batches
  - Per-item error handling
- **Advanced Features**
  - Convergent encryption for deduplication
  - Context-based encryption for multi-tenancy
  - AEAD with associated data
  - Key version selection
- **Envelope Encryption**
  - Generate data encryption keys (DEK)
  - Wrapped DEK generation
  - Hybrid encryption pattern support

#### Phase 4: Signing & Verification
- **Digital Signatures**
  - RSA signatures (PSS and PKCS#1v15)
  - ECDSA signatures (ASN.1 and JWS formats)
  - Ed25519 signatures
  - Multiple hash algorithms (SHA2, SHA3)
- **HMAC Operations**
  - HMAC generation for message authentication
  - HMAC verification
  - Support for multiple algorithms
- **Batch Operations**
  - Batch signing (up to 1000 signatures)
  - Batch verification
  - Automatic chunking
- **Flexibility**
  - Prehashed data support
  - Key version selection
  - Algorithm customization

#### Phase 5: Random Data Generation
- **Cryptographically Secure Random**
  - Generate random bytes (1 byte to 1MB)
  - Multiple entropy sources (platform, seal, both)
  - Multiple output formats (base64, hex)
- **Convenience Methods**
  - GenerateRandomBytes() for base64 output
  - GenerateRandomHex() for hex output

#### Phase 6: Hash Operations
- **Cryptographic Hashing**
  - SHA2-224, SHA2-256, SHA2-384, SHA2-512
  - SHA3-256, SHA3-384, SHA3-512
  - Multiple output formats (hex, base64)
- **Use Cases**
  - Data integrity verification
  - Prehashing for signatures
  - General-purpose hashing

#### Phase 7: Documentation & Examples
- **Comprehensive README**
  - Feature overview and quick start
  - Detailed API documentation
  - Best practices and patterns
  - Configuration guide
- **Example Programs**
  - Simple encryption/decryption
  - Batch operations demo
  - Digital signatures and HMAC
- **Developer Documentation**
  - Error handling examples
  - Performance notes
  - Testing guidelines

#### Phase 8: Testing & Quality
- **Unit Tests**
  - 317 test functions
  - Comprehensive input validation
  - Options structures testing
  - Result structures testing
- **Integration Tests**
  - 88 integration test scenarios
  - Real OpenBao testing with testcontainers
  - Complete operation coverage
  - Edge case testing
- **Benchmarks**
  - Operation benchmarking framework
  - Batch size performance testing
  - Encoding overhead measurement

### Test Coverage

- **Unit Tests**: All passing ✅
- **Integration Tests**: All passing ✅
- **Total Test Functions**: 317
- **Integration Scenarios**: 88
- **Code Coverage**: Comprehensive across all modules

### Performance Features

- Automatic batch chunking (default: 250, max: 1000)
- HTTP connection pooling
- Configurable timeouts
- Efficient base64 encoding/decoding
- Memory-safe ephemeral key handling (memguard)

### Files Added

#### Core Implementation
- `client.go` - Client initialization and HTTP operations
- `config.go` - Configuration management
- `types.go` - Common types and constants
- `errors.go` - Error handling

#### Key Management
- `key.go` - Key lifecycle operations
- `key_wrapping.go` - Import/export/backup/restore

#### Cryptographic Operations
- `encrypt.go` - Encryption/decryption operations
- `sign.go` - Signing/verification/HMAC
- `random.go` - Random data generation
- `hash.go` - Hash operations

#### Testing
- `*_test.go` - Unit tests for each module
- `*_integration_test.go` - Integration tests
- `integration_helpers_test.go` - Test utilities
- `benchmark_test.go` - Performance benchmarks

#### Documentation
- `README.md` - Main documentation
- `CHANGELOG.md` - This file
- `examples/` - Example programs

### Dependencies

- `github.com/openbao/openbao/api` - OpenBao API client
- `github.com/awnumar/memguard` - Secure memory handling
- `github.com/testcontainers/testcontainers-go` - Integration testing

### Breaking Changes

None - Initial release (v1.0.0)

### Migration Guide

Not applicable - Initial release

### Known Limitations

1. Random data generation limited to 1MB per call
2. Batch operations limited to 1000 items per call
3. Requires OpenBao server with Transit secrets engine enabled

### Security Considerations

- All sensitive data should be base64-encoded
- Use context-based encryption for multi-tenancy
- Enable key rotation for long-lived keys
- Use envelope encryption for large data
- Store encrypted data with ciphertext (includes version info)
- Use memguard for ephemeral key material

### Future Enhancements

Potential future additions (not implemented in v1.0.0):
- Cache configuration operations
- Advanced retry logic with exponential backoff
- Metrics and observability hooks
- Custom HTTP client injection
- Streaming operations for very large data

## Contributing

Contributions welcome! Please ensure:
1. All unit tests pass
2. All integration tests pass
3. Code is formatted with `go fmt`
4. Documentation is updated
5. Benchmarks show no regression

## License

See main repository LICENSE file.

## Authors

- Implementation: Claude Code with Anthropic
- Specification: Based on OpenBao Transit Secrets Engine API

## Acknowledgments

- OpenBao project for the excellent Transit secrets engine
- Go community for testing frameworks
- Testcontainers for integration testing support
