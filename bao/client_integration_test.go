//go:build integration

package bao

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_ClientHealth(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Test Health
	t.Run("Health check should pass", func(t *testing.T) {
		err := client.Health(ctx)
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
	})
}

func TestIntegration_ClientValidateConnection(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Wait for healthy
	if err := container.WaitForHealthy(ctx, 30*time.Second); err != nil {
		t.Fatalf("Container not healthy: %v", err)
	}

	// Enable PKI
	if err := container.EnablePKI(ctx, "pki", ""); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Test ValidateConnection
	t.Run("ValidateConnection should pass", func(t *testing.T) {
		err := client.ValidateConnection(ctx)
		if err != nil {
			t.Fatalf("ValidateConnection failed: %v", err)
		}
	})
}

func TestIntegration_ClientTimeout(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, _ := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Create client with very short timeout
	client, err := NewClient(&Config{
		Address: container.Address,
		Token:   container.Token,
		Mount:   "pki",
		Timeout: 1 * time.Nanosecond, // Extremely short timeout
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Health check should timeout
	t.Run("Health check should timeout", func(t *testing.T) {
		timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		err := client.Health(timeoutCtx)
		if err == nil {
			t.Fatal("Expected timeout error, got nil")
		}
	})
}
