// +build integration

package transit_test

import (
	"context"
	"testing"
)

// TestIntegration_ClientInitialization tests basic client setup and validation.
func TestIntegration_ClientInitialization(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Test Health check
	err := client.Health(ctx)
	if err != nil {
		t.Errorf("Health() error = %v, want nil", err)
	}

	// Test Ping (alias for Health)
	err = client.Ping(ctx)
	if err != nil {
		t.Errorf("Ping() error = %v, want nil", err)
	}

	// Test ValidateConnection
	err = client.ValidateConnection(ctx)
	if err != nil {
		t.Errorf("ValidateConnection() error = %v, want nil", err)
	}
}
