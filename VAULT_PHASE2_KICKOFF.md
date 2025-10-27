# Vault Integration - Phase 2 Kickoff

**Date:** 2025-10-27
**Status:** 🚀 Phase 2 Starting
**Branch:** feature/vault-integration
**Previous Phase:** Phase 1 Complete (82.4% coverage, 90+ test cases)

---

## Phase 2 Overview

**Objective:** Implement CA & Issuer Management, Key Management, and Role Management

**Timeline:** Days 1-7 (Week 2)
**Target Coverage:** 75%+ test coverage
**Expected LOC:** ~1,000-1,500 (production + tests)

---

## Phase 2 Scope

### 1. CA Operations (Days 1-3)

**New Functions in `issuer.go`:**
- `GenerateRootCA()` - Generate self-signed root CA in Vault
- `GenerateIntermediateCA()` - Generate intermediate CA
- `SignIntermediateCSR()` - Sign intermediate CA CSR
- `ImportCA()` - Import external CA bundle
- `GetIssuer()` - Get issuer details
- `ListIssuers()` - List all issuers
- `UpdateIssuer()` - Update issuer configuration
- `DeleteIssuer()` - Delete issuer
- `SetDefaultIssuer()` - Set default issuer

**Key Features:**
- Support for root and intermediate CAs
- CA hierarchy management
- Multi-issuer support
- CA bundle import/export

### 2. Issuer Management (Days 4-5)

**Issuer Operations:**
- CRUD operations for issuers
- Issuer configuration (URLs, CRL, OCSP)
- Default issuer management
- Issuer lifecycle management

**Types:**
- `IssuerInfo` - Issuer metadata
- `IssuerConfig` - Issuer configuration
- `CABundle` - CA certificate bundle

### 3. Key Management (Days 6-7)

**New Functions in `key.go`:**
- `GenerateKey()` - Generate key in Vault
- `ImportKey()` - Import GoPKI key to Vault
- `ListKeys()` - List all keys
- `GetKey()` - Get key details
- `DeleteKey()` - Delete key
- `UpdateKeyConfig()` - Update key configuration

**Key Features:**
- Support for RSA, ECDSA, Ed25519 keys
- Key import from GoPKI keypairs
- Key metadata management
- Secure key deletion

### 4. Role Management

**New Functions in `role.go`:**
- `CreateRole()` - Create/update role
- `GetRole()` - Get role configuration
- `ListRoles()` - List all roles
- `DeleteRole()` - Delete role

**Role Configuration:**
- Domain restrictions
- TTL settings
- Key usage settings
- Extended key usage
- Certificate policies

---

## Implementation Plan

### Day 1-3: CA Operations

#### File: `vault/issuer.go`

**1. Types and Structs:**
```go
type CAOptions struct {
    Type              string   // "root", "intermediate", "exported"
    CommonName        string
    Organization      []string
    Country           []string
    Locality          []string
    Province          []string
    StreetAddress     []string
    PostalCode        []string
    TTL               string
    KeyType           string   // "rsa", "ec", "ed25519"
    KeyBits           int
    MaxPathLength     int
    ExcludeCNFromSANs bool
    PermittedDNSDomains []string
    URISANs           []string
    IPSANs            []string
    AltNames          []string
}

type IntermediateCAOptions struct {
    Type         string // "internal", "exported"
    CommonName   string
    Organization []string
    Country      []string
    TTL          string
    KeyType      string
    KeyBits      int
    MaxPathLength int
    // ... more fields
}

type IssuerInfo struct {
    IssuerID             string
    IssuerName           string
    KeyID                string
    Certificate          string // PEM format
    CAChain              []string
    ManualChain          []string
    LeafNotAfterBehavior string
    Usage                string
    RevocationSignatureAlgorithm string
    IssuingCertificates  []string
    CRLDistributionPoints []string
    OCSPServers          []string
}

type IssuerConfig struct {
    IssuerName           string
    LeafNotAfterBehavior string
    Usage                string
    RevocationSignatureAlgorithm string
    IssuingCertificates  []string
    CRLDistributionPoints []string
    OCSPServers          []string
    EnableAIAURLTemplating bool
}

type CABundle struct {
    Certificate  string
    IssuingCA    string
    CAChain      []string
    PrivateKey   string   // Optional, for import
    PrivateKeyType string // "rsa", "ec", "ed25519"
}

type GenerateCAResponse struct {
    Certificate  *cert.Certificate
    IssuingCA    string
    CAChain      []string
    SerialNumber string
    IssuerID     string
    KeyID        string
}
```

**2. Functions:**

```go
// GenerateRootCA generates a self-signed root CA certificate in Vault
func (c *Client) GenerateRootCA(ctx context.Context, opts *CAOptions) (*GenerateCAResponse, error)

// GenerateIntermediateCA generates an intermediate CA certificate
// This can be either internal (Vault generates key) or exported (returns CSR)
func (c *Client) GenerateIntermediateCA(ctx context.Context, opts *IntermediateCAOptions) (*GenerateCAResponse, error)

// SignIntermediateCSR signs an intermediate CA CSR
func (c *Client) SignIntermediateCSR(ctx context.Context, csr *cert.CertificateSigningRequest, opts *CAOptions) (*cert.Certificate, error)

// ImportCA imports an existing CA bundle into Vault
func (c *Client) ImportCA(ctx context.Context, bundle *CABundle) (*IssuerInfo, error)

// GetIssuer retrieves issuer information by ID or name
func (c *Client) GetIssuer(ctx context.Context, issuerRef string) (*IssuerInfo, error)

// ListIssuers lists all issuers in the PKI mount
func (c *Client) ListIssuers(ctx context.Context) ([]string, error)

// UpdateIssuer updates issuer configuration
func (c *Client) UpdateIssuer(ctx context.Context, issuerRef string, config *IssuerConfig) error

// DeleteIssuer deletes an issuer
func (c *Client) DeleteIssuer(ctx context.Context, issuerRef string) error

// SetDefaultIssuer sets the default issuer for the PKI mount
func (c *Client) SetDefaultIssuer(ctx context.Context, issuerRef string) error

// GetDefaultIssuer retrieves the default issuer ID
func (c *Client) GetDefaultIssuer(ctx context.Context) (string, error)
```

#### Testing Strategy:
- Mock Vault responses for all CA operations
- Test CA hierarchy (root → intermediate → leaf)
- Test CA import with various bundle formats
- Test issuer CRUD operations
- Test multi-issuer scenarios
- Test default issuer management

### Day 4-5: Additional Issuer Features

**Issuer URL Configuration:**
```go
// ConfigureIssuerURLs sets issuing certificates and CRL distribution points
func (c *Client) ConfigureIssuerURLs(ctx context.Context, issuerRef string, config *IssuerURLConfig) error

type IssuerURLConfig struct {
    IssuingCertificates   []string
    CRLDistributionPoints []string
    OCSPServers           []string
    EnableAIAURLTemplating bool
}
```

**Issuer Rotation:**
```go
// RotateRoot rotates the root CA certificate
func (c *Client) RotateRoot(ctx context.Context, opts *CAOptions) (*GenerateCAResponse, error)
```

### Day 6-7: Key Management

#### File: `vault/key.go`

**1. Types:**
```go
type KeyInfo struct {
    KeyID       string
    KeyName     string
    KeyType     string // "rsa", "ec", "ed25519"
    KeyBits     int
}

type GenerateKeyOptions struct {
    KeyName string
    KeyType string // "rsa", "ec", "ed25519"
    KeyBits int    // For RSA: 2048, 3072, 4096; For EC: 224, 256, 384, 521
}

type ImportKeyOptions struct {
    KeyName string
    KeyType string
}
```

**2. Functions:**
```go
// GenerateKey generates a new key in Vault
func (c *Client) GenerateKey(ctx context.Context, opts *GenerateKeyOptions) (*KeyInfo, error)

// ImportKey imports a GoPKI key pair into Vault
// Only the private key is imported
func (c *Client) ImportKey(ctx context.Context, keyPair interface{}, opts *ImportKeyOptions) (*KeyInfo, error)

// ListKeys lists all keys in the PKI mount
func (c *Client) ListKeys(ctx context.Context) ([]string, error)

// GetKey retrieves key information (no private material)
func (c *Client) GetKey(ctx context.Context, keyRef string) (*KeyInfo, error)

// DeleteKey deletes a key from Vault
func (c *Client) DeleteKey(ctx context.Context, keyRef string) error

// UpdateKeyConfig updates key configuration
func (c *Client) UpdateKeyConfig(ctx context.Context, keyRef string, name string) error
```

#### Key Import Implementation:
```go
func (c *Client) ImportKey(ctx context.Context, keyPair interface{}, opts *ImportKeyOptions) (*KeyInfo, error) {
    var pemData string
    var keyType string

    switch kp := keyPair.(type) {
    case *algo.RSAKeyPair:
        pemData = string(kp.PrivateKeyPEM())
        keyType = "rsa"
    case *algo.ECDSAKeyPair:
        pemData = string(kp.PrivateKeyPEM())
        keyType = "ec"
    case *algo.Ed25519KeyPair:
        pemData = string(kp.PrivateKeyPEM())
        keyType = "ed25519"
    default:
        return nil, fmt.Errorf("vault: unsupported key pair type: %T", keyPair)
    }

    reqBody := map[string]interface{}{
        "pem_bundle": pemData,
    }

    if opts != nil && opts.KeyName != "" {
        reqBody["key_name"] = opts.KeyName
    }

    // POST to /v1/{mount}/keys/import
    // ... implementation
}
```

### Day 6-7: Role Management (if time permits)

#### File: `vault/role.go`

**1. Types:**
```go
type RoleOptions struct {
    IssuerRef              string
    TTL                    string
    MaxTTL                 string
    AllowLocalhost         bool
    AllowedDomains         []string
    AllowedDomainsTemplate bool
    AllowBareDomains       bool
    AllowSubdomains        bool
    AllowGlobDomains       bool
    AllowWildcardCertificates bool
    AllowAnyName           bool
    EnforceHostnames       bool
    AllowIPSANs            bool
    AllowedIPSANs          []string
    AllowedURISANs         []string
    AllowedOtherSANs       []string
    AllowedSerialNumbers   []string
    ServerFlag             bool
    ClientFlag             bool
    CodeSigningFlag        bool
    EmailProtectionFlag    bool
    KeyType                string // "rsa", "ec", "ed25519", "any"
    KeyBits                int
    SignatureBits          int
    UsePSS                 bool
    KeyUsage               []string
    ExtKeyUsage            []string
    ExtKeyUsageOIDs        []string
    UseCSRCommonName       bool
    UseCSRSANs             bool
    OrganizationUnit       []string
    Organization           []string
    Country                []string
    Locality               []string
    Province               []string
    StreetAddress          []string
    PostalCode             []string
    GenerateLease          bool
    NoStore                bool
    RequireCN              bool
    PolicyIdentifiers      []string
    BasicConstraintsValidForNonCA bool
    NotBeforeDuration      string
    CNValidations          []string
    AllowedUserIDs         []string
}

type Role struct {
    Name string
    *RoleOptions
}
```

**2. Functions:**
```go
// CreateRole creates or updates a role
func (c *Client) CreateRole(ctx context.Context, name string, opts *RoleOptions) error

// GetRole retrieves role configuration
func (c *Client) GetRole(ctx context.Context, name string) (*Role, error)

// ListRoles lists all roles
func (c *Client) ListRoles(ctx context.Context) ([]string, error)

// DeleteRole deletes a role
func (c *Client) DeleteRole(ctx context.Context, name string) error
```

---

## Testing Strategy

### Unit Tests

**1. CA Operations Tests (`issuer_test.go`):**
- TestGenerateRootCA (success, validation errors)
- TestGenerateIntermediateCA (internal, exported)
- TestSignIntermediateCSR (success, invalid CSR)
- TestImportCA (with/without private key)
- TestGetIssuer (success, not found)
- TestListIssuers (empty, multiple)
- TestUpdateIssuer (success, not found)
- TestDeleteIssuer (success, not found)
- TestSetDefaultIssuer (success, invalid)

**2. Key Management Tests (`key_test.go`):**
- TestGenerateKey (RSA, ECDSA, Ed25519)
- TestImportKey (all key types)
- TestListKeys (empty, multiple)
- TestGetKey (success, not found)
- TestDeleteKey (success, not found)
- TestUpdateKeyConfig (success, errors)

**3. Role Management Tests (`role_test.go`):**
- TestCreateRole (success, validation)
- TestGetRole (success, not found)
- TestListRoles (empty, multiple)
- TestDeleteRole (success, not found)
- TestRoleOptions (various configurations)

### Integration Tests

**1. CA Hierarchy Test:**
```go
func TestCAHierarchy(t *testing.T) {
    // 1. Generate root CA
    root, _ := client.GenerateRootCA(ctx, rootOpts)

    // 2. Generate intermediate CA
    intermediate, _ := client.GenerateIntermediateCA(ctx, intOpts)

    // 3. Issue certificate from intermediate
    cert, _ := client.IssueCertificateWithKeyPair(ctx, role, keyPair, opts)

    // Verify chain: cert → intermediate → root
}
```

**2. Key Import/Export Test:**
```go
func TestKeyImportExport(t *testing.T) {
    // 1. Generate key pair with GoPKI
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    // 2. Import to Vault
    keyInfo, _ := client.ImportKey(ctx, keyPair, opts)

    // 3. Generate CA with imported key
    ca, _ := client.GenerateRootCA(ctx, caOpts)

    // Verify CA uses imported key
}
```

---

## API Compatibility

### Vault PKI Endpoints Used

**CA Operations:**
- POST `/v1/{mount}/root/generate/{type}` - Generate root CA
- POST `/v1/{mount}/intermediate/generate/{type}` - Generate intermediate
- POST `/v1/{mount}/root/sign-intermediate` - Sign intermediate CSR
- POST `/v1/{mount}/config/ca` - Import CA bundle
- GET  `/v1/{mount}/issuer/{issuer_ref}` - Get issuer
- LIST `/v1/{mount}/issuers` - List issuers
- POST `/v1/{mount}/issuer/{issuer_ref}` - Update issuer
- DELETE `/v1/{mount}/issuer/{issuer_ref}` - Delete issuer

**Key Management:**
- POST `/v1/{mount}/keys/generate/{type}` - Generate key
- POST `/v1/{mount}/keys/import` - Import key
- LIST `/v1/{mount}/keys` - List keys
- GET  `/v1/{mount}/key/{key_ref}` - Get key
- DELETE `/v1/{mount}/key/{key_ref}` - Delete key

**Role Management:**
- POST `/v1/{mount}/roles/{name}` - Create/update role
- GET  `/v1/{mount}/roles/{name}` - Get role
- LIST `/v1/{mount}/roles` - List roles
- DELETE `/v1/{mount}/roles/{name}` - Delete role

---

## Success Metrics

| Metric | Target | Phase 1 Actual |
|--------|--------|----------------|
| Test Coverage | > 75% | 82.4% |
| Test Cases | > 40 | 90+ |
| Lines of Code | ~1,000-1,500 | ~2,900 |
| External Dependencies | 0 | 0 |
| API Endpoints | ~20 | 12 |

---

## Deliverables

### Code
- [x] `vault/issuer.go` - CA and issuer management (~300-400 lines)
- [x] `vault/key.go` - Key management (~200-300 lines)
- [x] `vault/role.go` - Role management (~200-300 lines)
- [x] `vault/issuer_test.go` - CA/issuer tests (~400-500 lines)
- [x] `vault/key_test.go` - Key management tests (~300-400 lines)
- [x] `vault/role_test.go` - Role management tests (~200-300 lines)

### Documentation
- [x] Update `vault/README.md` with Phase 2 features
- [x] Add CA hierarchy examples
- [x] Add key management examples
- [x] Add role management examples
- [x] Update API reference

### Examples
- [x] `vault/examples/ca_hierarchy/` - CA setup example
- [x] `vault/examples/key_import/` - Key import example
- [x] `vault/examples/role_config/` - Role configuration example

---

## Risk Assessment

### Known Challenges

**1. Generic Method Limitation**
- **Challenge:** Go doesn't support generic methods
- **Solution:** Use `interface{}` with runtime type assertions (proven in Phase 1)

**2. Vault API Complexity**
- **Challenge:** CA/issuer API has many configuration options
- **Solution:** Start with essential fields, expand as needed

**3. Key Import Security**
- **Challenge:** Importing private keys requires careful handling
- **Solution:** Use same CSR workflow patterns from Phase 1

**4. Testing Complexity**
- **Challenge:** CA hierarchy testing requires multiple steps
- **Solution:** Use HTTP mocks with stateful responses

### Mitigation Strategies

- Follow Phase 1 patterns (context usage, error handling)
- Use HTTP mocks for all tests (no external dependencies)
- Comprehensive validation before Vault API calls
- Clear error messages with context

---

## Implementation Order

### Day 1: Foundation
1. Create `issuer.go` with types
2. Implement `GenerateRootCA()`
3. Implement `GetIssuer()` and `ListIssuers()`
4. Basic tests

### Day 2: CA Operations
1. Implement `GenerateIntermediateCA()`
2. Implement `SignIntermediateCSR()`
3. Implement `ImportCA()`
4. CA hierarchy tests

### Day 3: Issuer Management
1. Implement `UpdateIssuer()`, `DeleteIssuer()`
2. Implement `SetDefaultIssuer()`
3. Implement issuer URL configuration
4. Complete issuer tests

### Day 4: Key Management Foundation
1. Create `key.go` with types
2. Implement `GenerateKey()`
3. Implement `ImportKey()` with type assertions
4. Basic key tests

### Day 5: Key Management Complete
1. Implement `ListKeys()`, `GetKey()`, `DeleteKey()`
2. Complete key management tests
3. Key import/export integration tests

### Day 6: Role Management
1. Create `role.go` with types
2. Implement role CRUD operations
3. Role management tests

### Day 7: Documentation and Polish
1. Update `vault/README.md`
2. Create examples
3. Run full test suite
4. Code review and refactoring

---

**Phase 2 Status: 🚀 Ready to Start**
**Branch:** feature/vault-integration
**Starting Point:** 6 commits, ~2,900 LOC, 82.4% coverage
**Target:** +1,000-1,500 LOC, 75%+ coverage, 40+ new test cases

**Date:** 2025-10-27
**Next:** Implement `vault/issuer.go` with CA operations
