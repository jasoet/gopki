// Package testcontainer provides OpenBao testcontainer utilities for integration testing.
// This package can be used by other projects that need to test against OpenBao.
package testcontainer

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/openbao/openbao/api/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Config contains configuration for the OpenBao test container.
type Config struct {
	// Image is the Docker image to use (default: "openbao/openbao:2.4.3")
	Image string

	// RootToken is the root token for the dev server (default: "root-token")
	RootToken string

	// Port is the OpenBao port (default: "8200/tcp")
	Port string

	// StartupTimeout is the maximum time to wait for container startup (default: 60s)
	StartupTimeout time.Duration

	// DevMode runs OpenBao in development mode (default: true)
	DevMode bool
}

// DefaultConfig returns the default configuration for OpenBao test container.
func DefaultConfig() *Config {
	return &Config{
		Image:          "openbao/openbao:2.4.3",
		RootToken:      "root-token",
		Port:           "8200/tcp",
		StartupTimeout: 60 * time.Second,
		DevMode:        true,
	}
}

// Container wraps a testcontainer running OpenBao.
type Container struct {
	container testcontainers.Container
	config    *Config
	Address   string
	Token     string
}

// Start creates and starts an OpenBao test container.
//
// Example:
//
//	ctx := context.Background()
//	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
//	if err != nil {
//	    t.Fatalf("Failed to start container: %v", err)
//	}
//	defer container.Terminate(ctx)
func Start(ctx context.Context, cfg *Config) (*Container, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Set defaults for any missing values
	if cfg.Image == "" {
		cfg.Image = "openbao/openbao:2.4.3"
	}
	if cfg.RootToken == "" {
		cfg.RootToken = "root-token"
	}
	if cfg.Port == "" {
		cfg.Port = "8200/tcp"
	}
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = 60 * time.Second
	}

	// Build environment variables
	env := map[string]string{
		"BAO_DEV_ROOT_TOKEN_ID":  cfg.RootToken,
		"BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
	}

	// Build command
	cmd := []string{"server"}
	if cfg.DevMode {
		cmd = append(cmd, "-dev")
	}

	// Create container request
	req := testcontainers.ContainerRequest{
		Image:        cfg.Image,
		ExposedPorts: []string{cfg.Port},
		Env:          env,
		Cmd:          cmd,
		WaitingFor: wait.ForAll(
			wait.ForLog("OpenBao server started!"),
			wait.ForHTTP("/v1/sys/health").WithPort(nat.Port(cfg.Port)).WithStatusCodeMatcher(func(status int) bool {
				// OpenBao returns various status codes when healthy
				// 200: active, 429: standby, 473: performance standby, 501: not initialized
				return status == 200 || status == 429 || status == 473 || status == 501
			}),
		).WithDeadline(cfg.StartupTimeout),
	}

	// Start container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}

	// Get host and port
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "8200")
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("get container port: %w", err)
	}

	address := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	return &Container{
		container: container,
		config:    cfg,
		Address:   address,
		Token:     cfg.RootToken,
	}, nil
}

// Terminate stops and removes the OpenBao container.
func (c *Container) Terminate(ctx context.Context) error {
	if c.container == nil {
		return nil
	}
	return c.container.Terminate(ctx)
}

// EnablePKI enables the PKI secrets engine at the specified mount path.
// If maxLeaseTTL is empty, defaults to "87600h" (10 years).
//
// Example:
//
//	err := container.EnablePKI(ctx, "pki", "87600h")
//	if err != nil {
//	    t.Fatalf("Failed to enable PKI: %v", err)
//	}
func (c *Container) EnablePKI(ctx context.Context, mountPath string, maxLeaseTTL string) error {
	if maxLeaseTTL == "" {
		maxLeaseTTL = "87600h" // 10 years
	}

	return c.enableSecretsEngine(ctx, mountPath, "pki", &api.MountConfigInput{
		MaxLeaseTTL: maxLeaseTTL,
	})
}

// EnableKV enables the KV (Key-Value) secrets engine at the specified mount path.
// Version can be 1 or 2. If version is 0, defaults to version 2.
//
// Example:
//
//	err := container.EnableKV(ctx, "secret", 2)
//	if err != nil {
//	    t.Fatalf("Failed to enable KV: %v", err)
//	}
func (c *Container) EnableKV(ctx context.Context, mountPath string, version int) error {
	if version == 0 {
		version = 2
	}

	engineType := "kv"
	var options map[string]string
	if version == 2 {
		engineType = "kv-v2"
		options = map[string]string{"version": "2"}
	}

	return c.enableSecretsEngine(ctx, mountPath, engineType, &api.MountConfigInput{
		Options: options,
	})
}

// EnableTransit enables the Transit secrets engine at the specified mount path.
// Transit provides encryption as a service.
//
// Example:
//
//	err := container.EnableTransit(ctx, "transit")
//	if err != nil {
//	    t.Fatalf("Failed to enable Transit: %v", err)
//	}
func (c *Container) EnableTransit(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "transit", nil)
}

// EnableDatabase enables the Database secrets engine at the specified mount path.
// Database provides dynamic database credentials.
//
// Example:
//
//	err := container.EnableDatabase(ctx, "database")
//	if err != nil {
//	    t.Fatalf("Failed to enable Database: %v", err)
//	}
func (c *Container) EnableDatabase(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "database", nil)
}

// EnableSSH enables the SSH secrets engine at the specified mount path.
// SSH provides SSH credentials and certificate signing.
//
// Example:
//
//	err := container.EnableSSH(ctx, "ssh")
//	if err != nil {
//	    t.Fatalf("Failed to enable SSH: %v", err)
//	}
func (c *Container) EnableSSH(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "ssh", nil)
}

// EnableTOTP enables the TOTP secrets engine at the specified mount path.
// TOTP provides time-based one-time passwords.
//
// Example:
//
//	err := container.EnableTOTP(ctx, "totp")
//	if err != nil {
//	    t.Fatalf("Failed to enable TOTP: %v", err)
//	}
func (c *Container) EnableTOTP(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "totp", nil)
}

// EnableAWS enables the AWS secrets engine at the specified mount path.
// AWS provides dynamic AWS credentials.
//
// Example:
//
//	err := container.EnableAWS(ctx, "aws")
//	if err != nil {
//	    t.Fatalf("Failed to enable AWS: %v", err)
//	}
func (c *Container) EnableAWS(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "aws", nil)
}

// EnableGCP enables the GCP secrets engine at the specified mount path.
// GCP provides dynamic GCP credentials.
//
// Example:
//
//	err := container.EnableGCP(ctx, "gcp")
//	if err != nil {
//	    t.Fatalf("Failed to enable GCP: %v", err)
//	}
func (c *Container) EnableGCP(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "gcp", nil)
}

// EnableRabbitMQ enables the RabbitMQ secrets engine at the specified mount path.
// RabbitMQ provides dynamic RabbitMQ credentials.
//
// Example:
//
//	err := container.EnableRabbitMQ(ctx, "rabbitmq")
//	if err != nil {
//	    t.Fatalf("Failed to enable RabbitMQ: %v", err)
//	}
func (c *Container) EnableRabbitMQ(ctx context.Context, mountPath string) error {
	return c.enableSecretsEngine(ctx, mountPath, "rabbitmq", nil)
}

// enableSecretsEngine is a helper function to enable any secrets engine.
// This is the common implementation used by all Enable* methods.
func (c *Container) enableSecretsEngine(ctx context.Context, mountPath, engineType string, config *api.MountConfigInput) error {
	// Create OpenBao SDK client
	apiConfig := api.DefaultConfig()
	apiConfig.Address = c.Address

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return fmt.Errorf("create SDK client: %w", err)
	}

	client.SetToken(c.Token)

	// Prepare mount input
	mountInput := &api.MountInput{
		Type: engineType,
	}
	if config != nil {
		mountInput.Config = *config
	}

	// Enable secrets engine
	err = client.Sys().MountWithContext(ctx, mountPath, mountInput)
	if err != nil {
		return fmt.Errorf("mount %s at %s: %w", engineType, mountPath, err)
	}

	return nil
}


// WaitForHealthy waits for OpenBao to become healthy with exponential backoff.
// Returns error if OpenBao doesn't become healthy within timeout.
func (c *Container) WaitForHealthy(ctx context.Context, timeout time.Duration) error {
	// Create OpenBao SDK client
	apiConfig := api.DefaultConfig()
	apiConfig.Address = c.Address

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return fmt.Errorf("create SDK client: %w", err)
	}

	client.SetToken(c.Token)

	deadline := time.Now().Add(timeout)
	backoff := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		healthResp, err := client.Sys().HealthWithContext(ctx)
		if err == nil && healthResp.Initialized && !healthResp.Sealed {
			return nil
		}

		time.Sleep(backoff)
		backoff *= 2
		if backoff > 2*time.Second {
			backoff = 2 * time.Second
		}
	}

	return fmt.Errorf("OpenBao did not become healthy within %v", timeout)
}

// Config returns the container configuration.
func (c *Container) Config() *Config {
	return c.config
}
