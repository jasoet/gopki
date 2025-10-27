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

