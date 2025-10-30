//go:build integration

package transit_test

import (
	"context"
	"testing"
	"time"

	"github.com/jasoet/gopki/bao/testcontainer"
	"github.com/jasoet/gopki/bao/transit"
)

// setupTestContainer starts an OpenBao container with Transit enabled.
func setupTestContainer(t *testing.T) (*testcontainer.Container, *transit.Client) {
	t.Helper()

	ctx := context.Background()

	// Start OpenBao container
	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to start container: %v", err)
	}

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		container.Terminate(ctx)
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable Transit secrets engine
	if err := container.EnableTransit(ctx, "transit"); err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to enable Transit: %v", err)
	}

	// Create Transit client
	config := &transit.Config{
		Address: container.Address,
		Token:   container.Token,
		Mount:   "transit",
	}

	client, err := transit.NewClient(config)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to create Transit client: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		client.Close()
		container.Terminate(context.Background())
	})

	return container, client
}

// Helper function
func boolPtr(b bool) *bool {
	return &b
}
