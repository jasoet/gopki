//go:build integration

package vault

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_ClientHealth(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)

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

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)

	// Wait for Vault to be ready
	vaultContainer.WaitForVaultReady(ctx, t, client)

	// Enable PKI
	vaultContainer.EnablePKI(ctx, t, client)

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

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client with very short timeout
	client, err := NewClient(&Config{
		Address: vaultContainer.Address,
		Token:   vaultContainer.Token,
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
