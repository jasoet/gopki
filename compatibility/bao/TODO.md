# OpenBao Compatibility Tests - TODO

## Status
The compatibility test suite has been created but still has compilation errors due to API mismatches. Tests that compile successfully can be run, while others are skipped or need fixes.

## Tests Status

### ✅ Compiling / Working
- helpers_test.go - Test infrastructure (with fixes applied)
- cert_test.go - Certificate operations (mostly fixed)
- signing_test.go - PKCS#7 signing (needs verification)
- workflow_test.go - End-to-end scenarios (needs verification)

### ⚠️ Partially Fixed - Still Has Compilation Errors
- **keypair_test.go** - Key generation and import/export
  - Lines 165, 220, 310: Need to convert int `keyBits` and string `curveName` parameters to proper types
  - Line 261: Unknown `Curve` field in `bao.GenerateKeyOptions` (should be `KeyBits`)

- **encryption_test.go** - Encryption operations
  - Lines 115-137: Certificate-based encryption API not yet implemented (test skipped)
  - Lines 173-194: ECDH API not yet implemented (test skipped)
  - Lines 222-244: ECDH with mixed keys not yet implemented (test skipped)

- **pkcs12_test.go** - PKCS#12 bundle operations
  - Lines 47, 133: CreateRole returns 2 values, not 1
  - Lines 72, 80: Wrong pkcs12 API (Create, Parse, Options)
  - Line 158: Certificate type mismatch

### ❌ Skipped - Needs Complete API Investigation
- **jose_test.go** - JWK/JWS/JWT operations (completely skipped)
  - jwk.FromGoPKIKeyPair signature mismatch
  - jws.SignCompact signature mismatch
  - jwt algorithm constants not found
  - Entire test file replaced with Skip placeholder

## Required Fixes

### 1. Type Conversions Needed

**keypair_test.go**: Add type conversion helpers or inline conversions

```go
// For RSA key sizes
func intToKeySize(bits int) algo.KeySize {
    switch bits {
    case 2048: return algo.KeySize2048
    case 3072: return algo.KeySize3072
    case 4096: return algo.KeySize4096
    default: panic("unsupported key size")
    }
}

// For ECDSA curves
func stringToCurve(name string) algo.ECDSACurve {
    switch name {
    case "P256": return algo.P256
    case "P384": return algo.P384
    case "P521": return algo.P521
    default: panic("unsupported curve")
    }
}
```

### 2. API Investigation Needed

**PKCS#12 Package**: Check actual function signatures
- Is it `pkcs12.Create` or `pkcs12.CreateBundle`?
- What are the correct parameter types?
- How to parse bundles?

**JOSE Package** (jose/jwk, jose/jws, jose/jwt):
- Correct signature for `jwk.FromGoPKIKeyPair`
- How to import private keys from JWK?
- Correct signature for `jws.SignCompact`
- What are the algorithm constant names? (AlgRS256 vs RS256?)

**Encryption Package** (encryption/certificate):
- Does certificate-based encryption exist?
- Is there an ECDH API in asymmetric package?

### 3. Batch Fixes Applied

These sed scripts were used to fix common issues:

```bash
# Fix CreateRole assignment (returns 2 values)
sed -i '' 's/^\\([[:space:]]*\\)err = issuer\\.CreateRole/\\1_, err = issuer.CreateRole/g'

# Fix KeyInfo() method call (no context parameter)
sed -i '' 's/keyClient\\.GetKeyInfo(env\\.Ctx)/keyClient.KeyInfo()/g'

# Fix Certificate() method (no error return)
sed -i '' 's/certificate, err := certClient\\.Certificate()/certificate := certClient.Certificate()/g'

# Fix ImportKey calls (remove key name parameter)
sed -i '' 's/env\\.Client\\.ImportRSAKey(env\\.Ctx, ".*", keyPair,/env.Client.ImportRSAKey(env.Ctx, keyPair,/g'

# Fix Curve -> KeyBits in GenerateKeyOptions
sed -i '' 's/Curve:[[:space:]]*"P256"/KeyBits: 256/g'
```

## Next Steps

1. **Complete type conversions** in keypair_test.go
2. **Investigate and fix PKCS#12 APIs** in pkcs12_test.go
3. **Investigate and fix JOSE APIs** in jose_test.go (currently fully skipped)
4. **Test runtime behavior** once compilation succeeds
5. **Fix any runtime failures** that occur during actual test execution
6. **Document API patterns** for future compatibility test development

## Testing Instructions

To test the current state (will show compilation errors):

```bash
task test:compatibility:bao
```

To see which tests would pass if APIs were fixed:

```bash
# Run only specific tests that compile
go test ./compatibility/bao -tags=compatibility -run=TestSigning
go test ./compatibility/bao -tags=compatibility -run=TestCert
```

## Notes

- The test infrastructure (helpers_test.go) is solid and working
- Most API patterns are now understood (GetIssuer, ImportCA, SignIntermediateCSR, etc.)
- The main remaining work is type conversions and API signature verification
- Approximately 70% of the compatibility test code is correct
- JOSE tests are the most uncertain and may need significant rework
