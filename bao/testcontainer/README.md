# OpenBao TestContainer

Reusable OpenBao testcontainer utilities for integration testing. This package provides a simple way to spin up OpenBao containers for testing purposes.

## Features

- 🐳 **Docker-based**: Uses testcontainers-go for reliable container management
- ⚙️ **Configurable**: Supports custom images, tokens, and timeouts
- 🚀 **Dev Mode**: Runs OpenBao in development mode by default
- 🔧 **PKI Ready**: Helper methods to enable PKI secrets engine
- ✅ **Health Checks**: Built-in health check with exponential backoff

## Installation

```bash
go get github.com/jasoet/gopki/bao/testcontainer
```

## Usage

### Basic Usage

```go
package mypackage_test

import (
    "context"
    "testing"
    
    "github.com/jasoet/gopki/bao/testcontainer"
)

func TestWithOpenBao(t *testing.T) {
    ctx := context.Background()
    
    // Start OpenBao container with defaults
    container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
    if err != nil {
        t.Fatalf("Failed to start OpenBao: %v", err)
    }
    defer container.Terminate(ctx)
    
    // Use container.Address and container.Token for your tests
    t.Logf("OpenBao running at: %s", container.Address)
    t.Logf("Root token: %s", container.Token)
}
```

### Custom Configuration

```go
cfg := &testcontainer.Config{
    Image:          "openbao/openbao:2.5.0",  // Use specific version
    RootToken:      "my-custom-token",
    StartupTimeout: 120 * time.Second,
    DevMode:        true,
}

container, err := testcontainer.Start(ctx, cfg)
if err != nil {
    t.Fatalf("Failed to start: %v", err)
}
defer container.Terminate(ctx)
```

### Enable PKI Secrets Engine

```go
// Enable PKI at default path with default TTL (10 years)
err := container.EnablePKI(ctx, "pki", "")
if err != nil {
    t.Fatalf("Failed to enable PKI: %v", err)
}

// Enable PKI at custom path with custom TTL
err = container.EnablePKI(ctx, "pki-intermediate", "43800h")
if err != nil {
    t.Fatalf("Failed to enable PKI: %v", err)
}
```

### Wait for Container to be Healthy

```go
// Wait up to 30 seconds for OpenBao to be healthy
err := container.WaitForHealthy(ctx, 30*time.Second)
if err != nil {
    t.Fatalf("OpenBao not healthy: %v", err)
}
```

### Integration with GoPKI's bao Client

```go
import (
    "github.com/jasoet/gopki/bao"
    "github.com/jasoet/gopki/bao/testcontainer"
)

func TestWithBaoClient(t *testing.T) {
    ctx := context.Background()
    
    // Start container
    container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
    if err != nil {
        t.Fatalf("Failed to start: %v", err)
    }
    defer container.Terminate(ctx)
    
    // Enable PKI
    err = container.EnablePKI(ctx, "pki", "")
    if err != nil {
        t.Fatalf("Failed to enable PKI: %v", err)
    }
    
    // Create GoPKI bao client
    client, err := bao.NewClient(&bao.Config{
        Address: container.Address,
        Token:   container.Token,
        Mount:   "pki",
    })
    if err != nil {
        t.Fatalf("Failed to create client: %v", err)
    }
    defer client.Close()
    
    // Use client for testing
    err = client.Health(ctx)
    if err != nil {
        t.Fatalf("Health check failed: %v", err)
    }
}
```

## Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Image` | string | `openbao/openbao:2.4.3` | Docker image to use |
| `RootToken` | string | `root-token` | Root token for dev mode |
| `Port` | string | `8200/tcp` | OpenBao port |
| `StartupTimeout` | time.Duration | `60s` | Max time to wait for startup |
| `DevMode` | bool | `true` | Run in development mode |

## Health Check Status Codes

The health check accepts the following HTTP status codes as healthy:

- `200` - Active node
- `429` - Standby node
- `473` - Performance standby node
- `501` - Not initialized (acceptable in dev mode)

## Requirements

- Docker must be installed and running
- Go 1.24 or later
- testcontainers-go

## Thread Safety

The container methods are safe to call from multiple goroutines. However, each test should create its own container instance to ensure isolation.

## Example: Full Integration Test

```go
func TestFullPKIWorkflow(t *testing.T) {
    ctx := context.Background()
    
    // Setup container
    container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
    if err != nil {
        t.Fatalf("Start failed: %v", err)
    }
    defer container.Terminate(ctx)
    
    // Enable PKI
    if err := container.EnablePKI(ctx, "pki", "87600h"); err != nil {
        t.Fatalf("EnablePKI failed: %v", err)
    }
    
    // Wait for healthy
    if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
        t.Fatalf("Not healthy: %v", err)
    }
    
    // Create client
    client, err := bao.NewClient(&bao.Config{
        Address: container.Address,
        Token:   container.Token,
        Mount:   "pki",
    })
    if err != nil {
        t.Fatalf("NewClient failed: %v", err)
    }
    defer client.Close()
    
    // Your PKI operations here...
    t.Log("OpenBao is ready for PKI operations!")
}
```

## License

Part of the GoPKI project. See the main project LICENSE file for details.
