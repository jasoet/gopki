# Claude Code Development Guide

**Essential development guidelines for AI assistants working on GoPKI.**

## 🚀 Quick Start for AI Agents

**First 3 files to read (in order):**
1. [README.md](README.md) - Project overview with AI Agent Instructions
2. [docs/AI_NAVIGATION.md](docs/AI_NAVIGATION.md) - Comprehensive navigation guide
3. This file (CLAUDE.md) - Development workflows and commands

## 📚 Documentation Navigation

### For AI Assistants

**Start Here:**
- [README.md](README.md) - AI Agent Instructions section with quick navigation
- [docs/AI_NAVIGATION.md](docs/AI_NAVIGATION.md) - **Most comprehensive AI guide**

**Module-Specific (with AI Quick Start sections):**
- [keypair/README.md](keypair/README.md) - Foundation module, file structure map
- [encryption/README.md](encryption/README.md) - Most complex module, detailed breakdown
- [signing/README.md](signing/README.md) - Digital signatures
- [cert/README.md](cert/README.md) - X.509 certificates
- [pkcs12/README.md](pkcs12/README.md) - PKCS#12 bundles

**Conceptual Documentation:**
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design and module relationships
- [docs/ALGORITHMS.md](docs/ALGORITHMS.md) - Algorithm selection guide
- [docs/OPENSSL_COMPAT.md](docs/OPENSSL_COMPAT.md) - OpenSSL integration guide

**Testing and Compatibility:**
- [docs/COMPATIBILITY_REPORT.md](docs/COMPATIBILITY_REPORT.md) - OpenSSL/SSH test results
- `compatibility/helpers.go` - OpenSSL integration utilities
- `*_test.go` files - Unit tests (80.3% coverage)

### For Human Developers

- [README.md](README.md) - Project overview and quick start
- Module READMEs for API documentation
- [examples/*/doc.md](examples/) - Working code examples
- This file for development commands

## 🛠️ Development Commands

### Using Taskfile (Recommended)

Install Task from https://taskfile.dev/installation/

```bash
# Show all available tasks
task

# Setup
task setup             # Initial project setup and dependency verification
```

### Testing (Primary Development Commands)

```bash
# Core testing
task test              # Run all tests with race detection (80.3% coverage)
task test:verbose      # Verbose test output with detailed results
task test:coverage     # Generate HTML coverage report
task test:specific -- TestName  # Run specific test by name

# Compatibility testing
task test:compatibility # OpenSSL and ssh-keygen compatibility tests
```

### Code Quality

```bash
# Formatting
task format            # Format all Go code (go fmt)
task format:check      # Verify code formatting without changes

# Linting
task lint              # Basic linting with go vet
task lint:full         # Comprehensive linting with golangci-lint
task lint:security     # Security-focused linting (gosec, ineffassign)
task deadcode          # Find unused/dead code
task unused:all        # Run all unused code detection tools
```

### Building and Examples

```bash
# Building
task build             # Build the entire module
task build:examples    # Build example binaries with 'example' build tag

# Examples
task examples:run      # Run all examples sequentially
task examples:keypair      # Key generation examples
task examples:certificates # Certificate examples
task examples:signing      # Signing examples
task examples:encryption   # Encryption examples
```

### Module Management

```bash
task mod:verify        # Verify module dependencies
task mod:tidy          # Clean up dependencies
task mod:update        # Update all dependencies to latest versions
```

### Cleanup

```bash
task clean             # Clean build artifacts and generated files
task clean:cache       # Clean Go build and test cache
task clean:all         # Clean everything including module cache
task examples:clean    # Clean example output directories
```

### CI/CD Pipeline

```bash
task ci                # Run complete CI pipeline locally
task ci:full           # Comprehensive CI with all checks and examples
task pre-commit        # Pre-commit checks (format, lint, basic tests)
task release:check     # Check if ready for release
```

### Documentation

```bash
task docs:generate     # Generate API documentation
task docs:serve        # Start godoc server on http://localhost:6060
```

### Git Operations

```bash
task git:status        # Show git status and current branch
task git:commit -- "message"  # Commit with standardized message format
```

### Manual Commands (Fallback)

If Taskfile is unavailable:

```bash
# Core testing
go test ./... -race -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Compatibility testing
go test -tags=compatibility ./compatibility/...

# Building
go build ./...
go mod verify && go mod tidy

# Code quality
go fmt ./...
go vet ./...

# Examples (with build tags)
go run -tags example ./examples/keypair/main.go
go run -tags example ./examples/certificates/main.go
go run -tags example ./examples/signing/main.go
go run -tags example ./examples/encryption/main.go
```

## 🏗️ Project Architecture

### Module Structure

```
keypair/     - Foundation: Type-safe key generation (75.3% coverage)
    ↓
cert/        - X.509 certificates and CA operations (74.3% coverage)
    ↓
├── signing/     - Digital signatures and PKCS#7 (79.8% coverage)
├── encryption/  - Multi-algorithm encryption (89.1% coverage)
└── pkcs12/      - PKCS#12 file management (79.1% coverage)
```

**Critical Understanding:**
- `keypair/` defines type constraints used by ALL modules
- Changes to `keypair/keypair.go:50-150` affect entire codebase
- See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for complete design

### Key Concepts

**Type Safety Through Generics:**
```go
// All modules use these constraints from keypair/
type PrivateKey interface {
    *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

type PublicKey interface {
    *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

type KeyPair interface {
    *algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}
```

**Envelope Encryption (Most Complex Feature):**
- Hybrid encryption: DEK (Data Encryption Key) + KEK (Key Encryption Key)
- Supports large data (GBs) and multiple recipients
- OpenSSL-compatible mode available
- See `encryption/envelope/envelope.go` and [docs/OPENSSL_COMPAT.md](docs/OPENSSL_COMPAT.md)

## 🔧 Development Workflows

### Adding New Feature

1. **Plan**: Use TodoWrite for complex tasks (3+ steps)
2. **Read**: Check module README and existing patterns
3. **Test First**: Write failing tests (TDD approach)
4. **Implement**: Follow existing patterns, maintain type safety
5. **Test**: `task test:specific -- TestName`
6. **Verify**: Check dependent modules aren't affected
7. **Document**: Update module README if public API changes

### Fixing Bugs

1. **Read Tests**: Start with `*_test.go` to understand expected behavior
2. **Reproduce**: Create failing test case
3. **Investigate**: Use [docs/AI_NAVIGATION.md](docs/AI_NAVIGATION.md) bug patterns
4. **Fix**: Maintain patterns and type safety
5. **Verify**: Run full test suite
6. **Compatibility**: Run `task test:compatibility`

### Adding OpenSSL Compatibility

1. **Research**: Read [docs/OPENSSL_COMPAT.md](docs/OPENSSL_COMPAT.md)
2. **Helper Functions**: Add to `compatibility/helpers.go`
3. **Test Bidirectionally**: Test GoPKI ↔ OpenSSL both ways
4. **Document**: Update [`docs/COMPATIBILITY_REPORT.md`](docs/COMPATIBILITY_REPORT.md)
5. **Verify**: `task test:compatibility`

### Running Tests

```bash
# Before making changes
task test

# During development
task test:specific -- TestYourFeature

# Before committing
task pre-commit

# Before release
task ci:full
```

## ⚠️ Important Rules

### Type Safety

- **NEVER** use `any` or `interface{}` in core APIs (only in metadata maps)
- **ALWAYS** use generic constraints from `keypair/keypair.go`
- **MAINTAIN** compile-time type checking
- **FOLLOW** existing type patterns exactly

### Security

- **Minimum RSA key size**: 2048 bits (enforced)
- **File permissions**: 0600 (private keys), 0700 (directories)
- **Random source**: `crypto/rand.Reader` only
- **No raw key material** exposure in APIs
- **Validate inputs** before cryptographic operations

### Error Handling

- **All functions** return explicit errors (no panics)
- **Wrap errors** with context: `fmt.Errorf("context: %w", err)`
- **No information leakage** in error messages

### Testing

- **Write tests first** (TDD approach)
- **Table-driven tests** for multiple cases
- **Run compatibility tests** for OpenSSL integration
- **Maintain 80%+ coverage**

### Documentation

- **Update module README** for public API changes
- **Add examples** for new features
- **Document limitations** clearly (e.g., Ed25519 certificate encryption)
- **Update [`docs/COMPATIBILITY_REPORT.md`](docs/COMPATIBILITY_REPORT.md)** for OpenSSL changes

## 🎯 Common Tasks

### Generate Keys

```bash
task examples:keypair
# See keypair/README.md for API details
```

### Create Certificates

```bash
task examples:certificates
# See cert/README.md for CA operations
```

### Sign Documents

```bash
task examples:signing
# See signing/README.md for PKCS#7 formats
```

### Encrypt Data

```bash
task examples:encryption
# See encryption/README.md for envelope encryption
```

### Test OpenSSL Compatibility

```bash
task test:compatibility
# See docs/OPENSSL_COMPAT.md for integration patterns
```

## 🐛 Troubleshooting

### Issue: Compile errors with generic types

**Solution**: Check type constraints in `keypair/keypair.go:50-150`

### Issue: Tests failing after changes

**Solution**:
1. Read test expectations in `*_test.go`
2. Check [docs/AI_NAVIGATION.md](docs/AI_NAVIGATION.md) for bug patterns
3. Verify type safety maintained

### Issue: OpenSSL compatibility broken

**Solution**:
1. Read [docs/OPENSSL_COMPAT.md](docs/OPENSSL_COMPAT.md)
2. Check `encryption/envelope/envelope.go:520-600` (OpenSSL mode)
3. Verify `opts.OpenSSLCompatible = true` for OpenSSL workflows
4. Run `task test:compatibility`

### Issue: Envelope encryption cycle broken

**Solution**:
1. Read `encryption/envelope/cms_cycle_test.go`
2. Check `encryption/cms.go:140-200` (DecodeFromCMS)
3. Verify envelope structure preserved (not prematurely decrypted)
4. Run `task test:specific -- TestCertificateEnvelopeEncryptionWithCMSCycle`

## 📋 Quality Checklist

Before committing:
- [ ] `task format` - Code formatted
- [ ] `task lint:security` - Security checks pass
- [ ] `task test` - All tests pass
- [ ] `task test:compatibility` - Compatibility tests pass (if relevant)
- [ ] Module README updated (if public API changed)
- [ ] Examples updated (if new feature)
- [ ] Type safety maintained (no `any` in core APIs)

Before releasing:
- [ ] `task ci:full` - Full CI pipeline passes
- [ ] Documentation complete
- [ ] Examples tested
- [ ] Compatibility verified

## 🔗 Key Resources

**For Development:**
- [Taskfile.yml](Taskfile.yml) - All development commands
- [go.mod](go.mod) - Dependencies and versions
- [.github/workflows/](.github/workflows/) - CI/CD configuration

**For Understanding Codebase:**
- [docs/AI_NAVIGATION.md](docs/AI_NAVIGATION.md) - **Most comprehensive guide for AI**
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
- [docs/ALGORITHMS.md](docs/ALGORITHMS.md) - Algorithm selection
- [docs/OPENSSL_COMPAT.md](docs/OPENSSL_COMPAT.md) - OpenSSL integration

**For Examples:**
- [examples/keypair/](examples/keypair/) - Key generation examples
- [examples/certificates/](examples/certificates/) - Certificate examples
- [examples/signing/](examples/signing/) - Signing examples
- [examples/encryption/](examples/encryption/) - Encryption examples
- [examples/pkcs12/](examples/pkcs12/) - PKCS#12 examples

## 📝 Notes

- **Test Coverage**: 80.3% overall (844+ tests)
- **Build Tags**: Examples use `//go:build example`, compatibility tests use `//go:build compatibility`
- **Go Version**: 1.24.5+ required for generics support
- **External Dependencies**: Minimal (PKCS#7, x/crypto, go-pkcs12)
- **Standards**: RFC 5652 (CMS), RFC 5280 (X.509), RFC 7748 (Ed25519), PKCS#7/12

---

**For comprehensive AI navigation, see [docs/AI_NAVIGATION.md](docs/AI_NAVIGATION.md)**