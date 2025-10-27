//go:build integration

package bao

import (
	"context"
	"testing"
	"time"

	"github.com/jasoet/gopki/bao/testcontainer"
)

// setupTestContainer is a convenience wrapper for integration tests.
// It starts an OpenBao container and returns a configured client.
func setupTestContainer(t *testing.T) (*testcontainer.Container, *Client) {
	t.Helper()

	ctx := context.Background()

	// Start container
	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to start OpenBao container: %v", err)
	}

	// Create client
	client, err := NewClient(&Config{
		Address: container.Address,
		Token:   container.Token,
		Mount:   "pki",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to create client: %v", err)
	}

	return container, client
}

// cleanupTestContainer terminates the container.
func cleanupTestContainer(t *testing.T, container *testcontainer.Container) {
	t.Helper()
	ctx := context.Background()
	if err := container.Terminate(ctx); err != nil {
		t.Logf("Failed to terminate container: %v", err)
	}
}

// VaultContainer is a compatibility wrapper for old integration tests
type VaultContainer struct {
	container *testcontainer.Container
	client    *Client
}

// Cleanup terminates the container
func (vc *VaultContainer) Cleanup(ctx context.Context, t *testing.T) {
	t.Helper()
	if err := vc.container.Terminate(ctx); err != nil {
		t.Logf("Failed to terminate container: %v", err)
	}
}

// CreateTestClient returns the client (already created)
func (vc *VaultContainer) CreateTestClient(t *testing.T) *Client {
	t.Helper()
	return vc.client
}

// WaitForVaultReady is a no-op since container is already initialized
func (vc *VaultContainer) WaitForVaultReady(ctx context.Context, t *testing.T, client *Client) error {
	t.Helper()
	_ = ctx
	_ = client
	return nil
}

// EnablePKI is a no-op since PKI is already enabled at "pki" mount
func (vc *VaultContainer) EnablePKI(ctx context.Context, t *testing.T, client *Client) error {
	t.Helper()
	_ = ctx
	_ = client
	return nil
}

// EnablePKIAtPath enables PKI at a custom mount path
func (vc *VaultContainer) EnablePKIAtPath(ctx context.Context, t *testing.T, client *Client, mountPath string) error {
	t.Helper()
	_ = client
	return vc.container.EnablePKI(ctx, mountPath, "")
}

// SetupVaultContainer is a compatibility function for old integration tests
// Deprecated: Use setupTestContainer instead
func SetupVaultContainer(ctx context.Context, t *testing.T) *VaultContainer {
	t.Helper()

	// Start container
	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to start OpenBao container: %v", err)
	}

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		container.Terminate(ctx)
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Create client
	client, err := NewClient(&Config{
		Address: container.Address,
		Token:   container.Token,
		Mount:   "pki",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to create client: %v", err)
	}

	return &VaultContainer{
		container: container,
		client:    client,
	}
}
