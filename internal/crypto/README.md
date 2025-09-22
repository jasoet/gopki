# GoPKI Internal Crypto Package

This package contains complex cryptographic algorithms that are not available in Go's standard library or well-established third-party libraries. These implementations are isolated here for easy review and maintenance.

## ⚠️ Security Notice

These implementations are provided for compatibility and educational purposes. They follow established RFCs and cryptographic standards, but should be thoroughly reviewed before production use.

## Algorithms Implemented

### 1. Ed25519 to X25519 Public Key Conversion (RFC 7748)

**File**: `curve25519.go`

**Purpose**: Converts Ed25519 public keys to X25519 public keys for ECDH operations.

**Mathematical Background**:
- Ed25519 uses Edwards25519 curve: `-x² + y² = 1 + d*x²*y²`
- X25519 uses Montgomery Curve25519: `B*v² = u³ + A*u² + u`
- Conversion formula: `u = (1 + y) / (1 - y) mod p`
- Prime field: `p = 2^255 - 19`

**References**:
- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm](https://tools.ietf.org/html/rfc8032)

**Usage**:
```go
ed25519PubKey := []byte{...} // 32 bytes
x25519PubKey, err := crypto.Ed25519ToX25519PublicKey(ed25519PubKey)
```

### 2. Field Arithmetic Operations

**File**: `bigint_ops.go`

**Purpose**: Provides modular arithmetic over the Curve25519 prime field.

**Operations**:
- Addition: `(a + b) mod p`
- Subtraction: `(a - b) mod p`
- Multiplication: `(a * b) mod p`
- Modular inverse: `a^(-1) mod p`

**Implementation**: Uses Go's `math/big` library for arbitrary precision arithmetic.

## Testing

Run tests with:
```bash
go test ./internal/crypto -v
```

Run benchmarks:
```bash
go test ./internal/crypto -bench=.
```

## Code Organization

```
internal/crypto/
├── curve25519.go       # Main Ed25519->X25519 conversion
├── bigint_ops.go       # Complex mathematical operations
├── curve25519_test.go  # Comprehensive tests
└── README.md          # This documentation
```

## Design Principles

1. **Isolation**: Complex algorithms are separated from main codebase
2. **Documentation**: Each function includes mathematical background
3. **Testing**: Comprehensive test coverage including edge cases
4. **Standards Compliance**: Follows established RFCs
5. **Reviewability**: Code is structured for easy security review

## Performance Notes

The Ed25519 to X25519 conversion involves:
- Big integer arithmetic operations
- Modular inverse calculation (most expensive operation)
- Field arithmetic over 255-bit prime

Expected performance: ~0.1-1ms per conversion on modern hardware.

## Future Enhancements

Potential optimizations:
1. **Native Field Arithmetic**: Replace big.Int with optimized field operations
2. **Precomputed Tables**: Cache common modular inverse values
3. **Assembly Optimizations**: Use platform-specific optimizations
4. **Constant-Time Operations**: Ensure timing attack resistance

## Security Considerations

1. **Side-Channel Resistance**: Current implementation may be vulnerable to timing attacks
2. **Input Validation**: All inputs are validated for correctness
3. **Error Handling**: Graceful handling of edge cases and invalid inputs
4. **Memory Safety**: No unsafe operations or manual memory management

## Maintenance

When updating these algorithms:
1. Maintain RFC compliance
2. Add comprehensive tests for any changes
3. Document mathematical reasoning
4. Consider security implications
5. Benchmark performance impact

---

**Note**: This package is internal to GoPKI and should not be used directly by external applications. Use the high-level encryption APIs instead.