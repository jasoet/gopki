//go:build integration

package bao

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// VaultContainer wraps a testcontainer running Vault/OpenBao
type VaultContainer struct {
	Container testcontainers.Container
	Address   string
	Token     string
}

// SetupVaultContainer starts a Vault container for integration testing
func SetupVaultContainer(ctx context.Context, t *testing.T) *VaultContainer {
	t.Helper()

	// Use OpenBao image (open source Vault fork)
	req := testcontainers.ContainerRequest{
		Image:        "openbao/openbao:2.4.3",
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"BAO_DEV_ROOT_TOKEN_ID":    "root-token", // OpenBao uses BAO_ prefix
			"BAO_DEV_LISTEN_ADDRESS":   "0.0.0.0:8200",
			"VAULT_DEV_ROOT_TOKEN_ID":  "root-token", // Keep for backward compat
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		},
		Cmd: []string{"server", "-dev"},
		WaitingFor: wait.ForAll(
			wait.ForLog("OpenBao server started!"), // OpenBao uses "OpenBao" not "Vault"
			wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStatusCodeMatcher(func(status int) bool {
				// OpenBao/Vault returns various status codes when healthy
				return status == 200 || status == 429 || status == 473 || status == 501
			}),
		).WithDeadline(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start Vault container: %v", err)
	}

	// Get the container's host and port
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to get container host: %v", err)
	}

	port, err := container.MappedPort(ctx, "8200")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to get container port: %v", err)
	}

	address := fmt.Sprintf("http://%s:%s", host, port.Port())

	return &VaultContainer{
		Container: container,
		Address:   address,
		Token:     "root-token",
	}
}

// Cleanup terminates the Vault container
func (vc *VaultContainer) Cleanup(ctx context.Context, t *testing.T) {
	t.Helper()
	if err := vc.Container.Terminate(ctx); err != nil {
		t.Logf("Failed to terminate Vault container: %v", err)
	}
}

// CreateTestClient creates a Vault client connected to the test container
func (vc *VaultContainer) CreateTestClient(t *testing.T) *Client {
	t.Helper()

	client, err := NewClient(&Config{
		Address: vc.Address,
		Token:   vc.Token,
		Mount:   "pki",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	return client
}

// EnablePKI enables the PKI secrets engine at the default mount
func (vc *VaultContainer) EnablePKI(ctx context.Context, t *testing.T, client *Client) {
	t.Helper()

	// Enable PKI secrets engine
	err := client.Sys().MountWithContext(ctx, "pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h", // 10 years
		},
	})
	if err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}
}

// EnablePKIAtPath enables the PKI secrets engine at a custom path
func (vc *VaultContainer) EnablePKIAtPath(ctx context.Context, t *testing.T, client *Client, path string) error {
	t.Helper()

	// Enable PKI secrets engine at custom path
	err := client.Sys().MountWithContext(ctx, path, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h", // 10 years
		},
	})
	return err
}

// WaitForVaultReady waits for Vault to be healthy
func (vc *VaultContainer) WaitForVaultReady(ctx context.Context, t *testing.T, client *Client) {
	t.Helper()

	// Wait for Vault to be ready
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		if err := client.Health(ctx); err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Vault did not become ready in time")
}
