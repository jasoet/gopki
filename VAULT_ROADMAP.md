# Vault PKI Integration - Roadmap & Future Development

**Document Version:** 1.0
**Last Updated:** 2025-10-27
**Current Status:** Phase 1 & 2 Complete ✅

---

## Executive Summary

The GoPKI Vault integration has successfully completed Phases 1 and 2, delivering a production-ready module for certificate operations and CA/key/role management. This document outlines the roadmap for Phase 3 (Advanced Features), Phase 4 (Production Readiness), and long-term enhancements.

### Current State

**Completed:**
- ✅ **Phase 1:** Certificate operations (5 functions, 82.4% coverage)
- ✅ **Phase 2:** CA/key/role management (22 functions, 78.6% coverage)
- ✅ **Total:** 30 functions, 130+ test cases, 100% pass rate

**Statistics:**
- Lines of Code: ~6,200 (including tests)
- Test Coverage: 78.6%
- Functions: 30 public APIs
- Test Cases: 130+
- Build Status: ✅ Clean
- Documentation: ✅ Complete

---

## Phase 3: Advanced Features

**Timeline:** 5-7 days
**Priority:** High
**Status:** 📋 Planned

### Overview

Phase 3 focuses on production-grade operational features that enhance the developer experience and enable real-world use cases at scale.

### 3.1 Certificate Rotation

**Goal:** Automatic certificate rotation with zero-downtime renewal

**Features:**
- Automatic certificate renewal before expiration
- Configurable renewal window (e.g., renew 30 days before expiry)
- Atomic rotation (new cert ready before old expires)
- Callbacks/hooks for rotation events
- Graceful handling of renewal failures with retry logic

**API Design:**

```go
type RotationConfig struct {
    // RenewalWindow is the time before expiration to trigger renewal
    RenewalWindow time.Duration // e.g., 30 days

    // CheckInterval is how often to check for expiration
    CheckInterval time.Duration // e.g., 1 hour

    // OnRenewal callback when certificate is renewed
    OnRenewal func(old, new *cert.Certificate) error

    // OnError callback when renewal fails
    OnError func(err error) error

    // MaxRetries for failed renewals
    MaxRetries int

    // RetryBackoff strategy
    RetryBackoff time.Duration
}

// StartRotation starts automatic certificate rotation
func (c *Client) StartRotation(ctx context.Context, config *RotationConfig) error

// StopRotation stops automatic rotation
func (c *Client) StopRotation() error

// RenewCertificate manually renews a certificate
func (c *Client) RenewCertificate(ctx context.Context, serial string) (*cert.Certificate, error)
```

**Implementation Tasks:**
1. Certificate expiration monitoring
2. Automatic renewal trigger logic
3. Callback/hook system
4. Retry mechanism with exponential backoff
5. Graceful shutdown handling
6. Comprehensive testing (rotation scenarios, failures)

**Test Coverage:**
- Happy path rotation
- Rotation with failures and retries
- Concurrent rotation handling
- Edge cases (cert already expired, rotation disabled mid-flight)

---

### 3.2 Auto-Renewal Support

**Goal:** Declarative certificate lifecycle management

**Features:**
- Watch pattern for certificate monitoring
- Automatic file updates on renewal
- Health check integration
- Metrics export (Prometheus format)

**API Design:**

```go
type AutoRenewalConfig struct {
    // Certificate serial or identifier
    CertificateRef string

    // Role to use for renewal
    Role string

    // KeyPair for CSR generation
    KeyPair interface{}

    // IssueOptions for renewal
    Options *IssueOptions

    // FilePath to automatically update
    CertPath string
    KeyPath  string

    // Permissions for updated files
    CertMode os.FileMode // default: 0644
    KeyMode  os.FileMode // default: 0600

    // Rotation configuration
    Rotation *RotationConfig
}

// EnableAutoRenewal enables automatic renewal for a certificate
func (c *Client) EnableAutoRenewal(ctx context.Context, config *AutoRenewalConfig) (string, error)

// DisableAutoRenewal stops auto-renewal by ID
func (c *Client) DisableAutoRenewal(renewalID string) error

// GetRenewalStatus gets status of auto-renewal
func (c *Client) GetRenewalStatus(renewalID string) (*RenewalStatus, error)
```

**Implementation Tasks:**
1. Renewal scheduler (background goroutine)
2. File watching and atomic updates
3. Status tracking and reporting
4. Integration with rotation system
5. Metrics collection
6. Health check endpoints

**Test Coverage:**
- Auto-renewal lifecycle
- File update atomicity
- Concurrent renewal handling
- Failure scenarios

---

### 3.3 Batch Operations

**Goal:** Efficient bulk certificate operations

**Features:**
- Bulk certificate issuance
- Bulk certificate revocation
- Batch CSR signing
- Parallel processing with rate limiting
- Progress tracking and reporting

**API Design:**

```go
type BatchIssueRequest struct {
    Role     string
    KeyPairs []interface{}
    Options  []*IssueOptions

    // Concurrency controls
    MaxConcurrent int           // default: 10
    RateLimit     time.Duration // delay between requests
}

type BatchIssueResult struct {
    Certificates []*cert.Certificate
    Errors       []error
    SuccessCount int
    FailureCount int
    Duration     time.Duration
}

// BatchIssueCertificates issues multiple certificates in parallel
func (c *Client) BatchIssueCertificates(ctx context.Context, req *BatchIssueRequest) (*BatchIssueResult, error)

// BatchRevokeCertificates revokes multiple certificates
func (c *Client) BatchRevokeCertificates(ctx context.Context, serials []string) (*BatchResult, error)

// BatchSignCSRs signs multiple CSRs
func (c *Client) BatchSignCSRs(ctx context.Context, role string, csrs []*cert.CertificateSigningRequest, opts *SignOptions) (*BatchIssueResult, error)
```

**Implementation Tasks:**
1. Worker pool for parallel processing
2. Rate limiting implementation
3. Progress tracking
4. Error aggregation and reporting
5. Context cancellation support
6. Memory-efficient streaming for large batches

**Test Coverage:**
- Batch operations (small, medium, large)
- Rate limiting effectiveness
- Error handling (partial failures)
- Cancellation scenarios

---

### 3.4 Metrics and Monitoring

**Goal:** Observability and operational insights

**Features:**
- Request metrics (count, duration, errors)
- Certificate lifecycle metrics
- Vault connection health
- Prometheus-compatible metrics export
- OpenTelemetry support

**API Design:**

```go
type Metrics struct {
    // Request metrics
    RequestsTotal     *prometheus.CounterVec
    RequestDuration   *prometheus.HistogramVec
    RequestErrors     *prometheus.CounterVec

    // Certificate metrics
    CertificatesIssued     *prometheus.Counter
    CertificatesRevoked    *prometheus.Counter
    CertificatesExpiring   *prometheus.GaugeVec // by time window

    // Connection metrics
    VaultConnectionStatus  *prometheus.Gauge
    VaultRequestRetries    *prometheus.Counter
}

// EnableMetrics enables Prometheus metrics collection
func (c *Client) EnableMetrics(registry *prometheus.Registry) error

// GetMetrics returns current metrics
func (c *Client) GetMetrics() *Metrics

// MetricsHandler returns HTTP handler for /metrics endpoint
func (c *Client) MetricsHandler() http.Handler
```

**Metrics to Track:**
- Request rate and latency (p50, p95, p99)
- Error rate by operation type
- Certificate issuance rate
- Certificate expiration timeline
- Vault connection health
- Auto-renewal success/failure rate

**Implementation Tasks:**
1. Prometheus client integration
2. Metric collection throughout codebase
3. HTTP metrics endpoint
4. OpenTelemetry trace export (optional)
5. Dashboard examples (Grafana)

**Test Coverage:**
- Metrics collection accuracy
- Metric endpoint functionality
- Label correctness

---

### 3.5 Connection Pool and Caching

**Goal:** Performance optimization for high-throughput scenarios

**Features:**
- HTTP connection pooling
- Response caching with TTL
- Request deduplication
- Circuit breaker for fault tolerance

**API Design:**

```go
type PoolConfig struct {
    MaxIdleConns        int           // default: 100
    MaxConnsPerHost     int           // default: 10
    IdleConnTimeout     time.Duration // default: 90s
    ResponseHeaderTimeout time.Duration // default: 10s
}

type CacheConfig struct {
    Enabled        bool
    TTL            time.Duration
    MaxSize        int // max cached items
    ExcludeSecrets bool // don't cache private keys
}

type CircuitBreakerConfig struct {
    Enabled           bool
    MaxFailures       int           // failures before opening
    ResetTimeout      time.Duration // time before retry
    HalfOpenRequests  int           // requests in half-open state
}

// WithPooling enables connection pooling
func WithPooling(config *PoolConfig) ClientOption

// WithCaching enables response caching
func WithCaching(config *CacheConfig) ClientOption

// WithCircuitBreaker enables circuit breaker
func WithCircuitBreaker(config *CircuitBreakerConfig) ClientOption
```

**Implementation Tasks:**
1. Custom HTTP transport with pooling
2. LRU cache implementation
3. Cache invalidation logic
4. Circuit breaker state machine
5. Performance benchmarks

**Test Coverage:**
- Connection reuse verification
- Cache hit/miss scenarios
- Cache TTL expiration
- Circuit breaker state transitions

---

### 3.6 Enhanced Error Handling

**Goal:** Detailed error context and recovery guidance

**Features:**
- Structured error types with context
- Retry recommendations
- Error categorization (transient vs permanent)
- Debug mode with detailed logging

**API Design:**

```go
type DetailedError struct {
    *VaultError

    // Additional context
    Request     interface{}  // sanitized request
    Response    interface{}  // sanitized response
    Timestamp   time.Time
    Duration    time.Duration
    Retryable   bool
    RetryAfter  time.Duration // suggested retry delay

    // Troubleshooting
    Suggestion  string
    DocsURL     string
}

// Helper functions
func IsTransient(err error) bool
func SuggestedRetryDelay(err error) time.Duration
func ErrorCategory(err error) string // "auth", "network", "validation", etc.
```

**Implementation Tasks:**
1. Enhanced error types
2. Error context collection
3. Retry heuristics
4. Troubleshooting suggestions
5. Documentation links

---

## Phase 4: Production Readiness

**Timeline:** 3-5 days
**Priority:** Medium
**Status:** 📋 Planned

### Overview

Phase 4 focuses on operational excellence, deployment readiness, and real-world validation.

### 4.1 Integration Testing

**Goal:** Validate against real Vault instance

**Features:**
- Docker-based Vault test environment
- Full E2E test suite
- Performance benchmarks
- Load testing

**Implementation:**

```yaml
# docker-compose.yml for testing
version: '3.8'
services:
  vault:
    image: hashicorp/vault:latest
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: test-token
    ports:
      - "8200:8200"
```

**Test Scenarios:**
- Complete CA hierarchy setup
- High-volume certificate issuance
- Concurrent operations
- Network failure scenarios
- Vault restart/recovery

**Deliverables:**
- Integration test suite (`vault/integration_test.go`)
- Docker Compose setup
- Load test scripts
- Performance benchmark results

---

### 4.2 Performance Benchmarks

**Goal:** Quantify performance characteristics

**Benchmarks:**
- Certificate issuance throughput
- CSR signing latency
- Batch operation scalability
- Memory usage under load
- Connection pool effectiveness

**Implementation:**

```go
// Example benchmark
func BenchmarkIssueCertificate(b *testing.B) {
    client := setupBenchmarkClient(b)
    keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := client.IssueCertificateWithKeyPair(ctx, "role", keyPair, opts)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

**Target Metrics:**
- Certificate issuance: > 100 certs/sec
- p99 latency: < 100ms
- Memory per certificate: < 100KB
- Connection reuse: > 90%

---

### 4.3 Production Deployment Guide

**Goal:** Comprehensive operational documentation

**Contents:**
1. **Architecture Overview**
   - Component diagram
   - Data flow
   - Security boundaries

2. **Deployment Patterns**
   - Single instance
   - High availability setup
   - Multi-region deployment
   - Disaster recovery

3. **Configuration Best Practices**
   - Connection settings
   - Timeout tuning
   - TLS configuration
   - Token management

4. **Monitoring Setup**
   - Metrics to watch
   - Alert thresholds
   - Dashboard templates
   - Log aggregation

5. **Troubleshooting Guide**
   - Common issues
   - Debug procedures
   - Performance tuning
   - Support escalation

**Deliverables:**
- `docs/PRODUCTION_GUIDE.md`
- Example configurations
- Monitoring templates
- Runbook procedures

---

### 4.4 Security Hardening

**Goal:** Security audit and hardening

**Tasks:**
1. **Code Review:**
   - Security-focused code audit
   - Dependency vulnerability scan
   - SAST (Static Application Security Testing)

2. **Hardening:**
   - Input validation review
   - Error message sanitization (no secret leakage)
   - Rate limiting for abuse prevention
   - Audit logging

3. **Documentation:**
   - Security best practices
   - Threat model
   - Incident response procedures

**Tools:**
- `gosec` for static analysis
- `govulncheck` for vulnerabilities
- `nancy` for dependency scanning

---

### 4.5 CI/CD Pipeline

**Goal:** Automated quality gates

**Pipeline Stages:**
1. **Build:** Compile all packages
2. **Unit Test:** Run unit tests (78.6% coverage)
3. **Integration Test:** Test against real Vault
4. **Benchmark:** Performance regression detection
5. **Security Scan:** Vulnerability scanning
6. **Lint:** Code quality checks
7. **Release:** Version tagging and artifact publishing

**GitHub Actions Workflow:**

```yaml
name: Vault Module CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      vault:
        image: hashicorp/vault:latest
        env:
          VAULT_DEV_ROOT_TOKEN_ID: test-token
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24'
      - run: go test -v -cover ./vault/...
      - run: go test -tags=integration ./vault/...

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: securego/gosec@master
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

---

## Phase 5: Advanced Integrations (Future)

**Timeline:** TBD
**Priority:** Low
**Status:** 🔮 Concept

### 5.1 Kubernetes Integration

**Features:**
- Kubernetes CertificateSigningRequest (CSR) controller
- Cert-manager integration
- Kubernetes Secret sync
- Service mesh integration (Istio, Linkerd)

**Example:**

```go
// Sync Vault certificates to Kubernetes Secrets
func (c *Client) SyncToKubernetes(ctx context.Context, config *K8sConfig) error
```

---

### 5.2 ACME Protocol Support

**Features:**
- ACME client implementation
- Let's Encrypt integration
- Automatic DNS-01 challenge
- HTTP-01 challenge support

**Example:**

```go
// Issue certificate via ACME protocol
func (c *Client) IssueViaACME(ctx context.Context, domain string) (*cert.Certificate, error)
```

---

### 5.3 Certificate Transparency (CT) Log

**Features:**
- Automatic CT log submission
- SCT (Signed Certificate Timestamp) verification
- CT log monitoring

**Example:**

```go
// Enable CT logging
func (c *Client) EnableCTLogging(config *CTConfig) error
```

---

### 5.4 Multi-Vault Support

**Features:**
- Multiple Vault backend support
- Automatic failover
- Load balancing across Vaults
- Federation support

**Example:**

```go
// Create client with multiple Vault endpoints
func NewMultiVaultClient(endpoints []string, config *Config) (*Client, error)
```

---

### 5.5 Webhook Support

**Features:**
- Certificate lifecycle webhooks
- Custom validation webhooks
- Approval workflows

**Example:**

```go
type WebhookConfig struct {
    URL     string
    Events  []string // "issue", "renew", "revoke"
    Headers map[string]string
}

func (c *Client) RegisterWebhook(config *WebhookConfig) error
```

---

## Implementation Priorities

### Must-Have (Phase 3)
1. ✅ Certificate Rotation (P0)
2. ✅ Auto-Renewal Support (P0)
3. ✅ Batch Operations (P1)
4. ✅ Metrics and Monitoring (P1)

### Should-Have (Phase 4)
1. ✅ Integration Testing (P1)
2. ✅ Performance Benchmarks (P2)
3. ✅ Production Guide (P2)
4. ✅ Security Hardening (P1)

### Nice-to-Have (Phase 5)
1. 🔮 Kubernetes Integration
2. 🔮 ACME Protocol
3. 🔮 CT Log Support
4. 🔮 Multi-Vault

---

## Success Metrics

### Phase 3 Goals
- Certificate rotation: < 1s downtime
- Auto-renewal: 99.9% success rate
- Batch operations: > 1000 certs/min
- Test coverage: > 80%

### Phase 4 Goals
- Integration tests: 100+ scenarios
- Performance: > 100 certs/sec
- Documentation: Complete production guide
- Security: Zero high-severity vulnerabilities

---

## Timeline Estimate

| Phase | Duration | Effort | Start Date |
|-------|----------|--------|------------|
| **Phase 1** | ✅ 2 days | ✅ Complete | Oct 26 |
| **Phase 2** | ✅ 2 days | ✅ Complete | Oct 27 |
| **Phase 3** | 5-7 days | ~40 hours | TBD |
| **Phase 4** | 3-5 days | ~24 hours | TBD |
| **Phase 5** | TBD | TBD | TBD |

---

## Risk Assessment

### Technical Risks

1. **Rotation Complexity**
   - Risk: Race conditions during rotation
   - Mitigation: Comprehensive locking, atomic operations
   - Impact: High
   - Probability: Medium

2. **Performance at Scale**
   - Risk: Memory leaks, connection exhaustion
   - Mitigation: Benchmarking, profiling, load testing
   - Impact: High
   - Probability: Low

3. **Vault API Changes**
   - Risk: Breaking changes in Vault API
   - Mitigation: Version testing, graceful degradation
   - Impact: Medium
   - Probability: Low

### Operational Risks

1. **Certificate Expiration**
   - Risk: Failed auto-renewal leading to outages
   - Mitigation: Multiple retry attempts, alerting
   - Impact: Critical
   - Probability: Medium

2. **Vault Downtime**
   - Risk: Vault unavailable during critical operations
   - Mitigation: Circuit breaker, graceful degradation
   - Impact: High
   - Probability: Low

---

## Dependencies

### External Dependencies
- HashiCorp Vault: 1.14+ or OpenBao
- Go: 1.24.5+ (generics support)
- Prometheus (optional): For metrics
- Docker (testing): For integration tests

### Internal Dependencies
- `github.com/jasoet/gopki/cert`
- `github.com/jasoet/gopki/keypair`
- Standard library only (no external deps for core)

---

## Maintenance Plan

### Regular Activities
1. **Weekly:**
   - Dependency updates check
   - Security vulnerability scan
   - Community issue triage

2. **Monthly:**
   - Performance benchmark run
   - Documentation review
   - Test coverage analysis

3. **Quarterly:**
   - Vault version compatibility testing
   - Security audit
   - Roadmap review

### Long-term Support
- Maintain compatibility with Vault LTS versions
- Provide migration guides for breaking changes
- Backport critical security fixes

---

## Community Engagement

### Documentation
- Comprehensive API documentation (GoDoc)
- Production deployment guide
- Troubleshooting runbook
- Video tutorials (YouTube)

### Examples
- Real-world use cases
- Integration examples (K8s, Docker, etc.)
- Performance optimization examples
- Security best practices

### Support Channels
- GitHub Discussions for Q&A
- GitHub Issues for bugs/features
- Slack channel (if demand exists)
- Stack Overflow tag

---

## Appendix: API Coverage

### Current Implementation (Phase 1 & 2)

**Client Operations (5):**
- ✅ NewClient
- ✅ Health
- ✅ ValidateConnection
- ✅ Ping
- ✅ doRequest (private)

**Certificate Operations (5):**
- ✅ IssueCertificateWithKeyPair
- ✅ SignCSR
- ✅ GetCertificate
- ✅ ListCertificates
- ✅ RevokeCertificate

**CA/Issuer Operations (11):**
- ✅ GenerateRootCA
- ✅ GenerateIntermediateCA
- ✅ SignIntermediateCSR
- ✅ ImportCA
- ✅ GetIssuer
- ✅ ListIssuers
- ✅ UpdateIssuer
- ✅ DeleteIssuer
- ✅ SetDefaultIssuer
- ✅ GetDefaultIssuer

**Key Management (7):**
- ✅ GenerateKey
- ✅ ImportKey
- ✅ ExportKey
- ✅ ListKeys
- ✅ GetKey
- ✅ UpdateKeyName
- ✅ DeleteKey

**Role Management (4):**
- ✅ CreateRole
- ✅ GetRole
- ✅ ListRoles
- ✅ DeleteRole

### Planned Phase 3 Additions (~10 functions)

**Rotation:**
- StartRotation
- StopRotation
- RenewCertificate
- GetRotationStatus

**Auto-Renewal:**
- EnableAutoRenewal
- DisableAutoRenewal
- GetRenewalStatus

**Batch Operations:**
- BatchIssueCertificates
- BatchRevokeCertificates
- BatchSignCSRs

**Metrics:**
- EnableMetrics
- GetMetrics
- MetricsHandler

---

**Document End**

*This roadmap is a living document and will be updated as priorities shift and new requirements emerge.*
