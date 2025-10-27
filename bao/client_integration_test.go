//go:build integration

package bao

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
)

func TestIntegration_NewClient(t *testing.T) {
	// Setup container
	container, _ := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Create client successfully", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: container.Address,
			Token:   container.Token,
			Mount:   "pki",
		})
		if err != nil {
			t.Fatalf("NewClient() failed: %v", err)
		}
		defer client.Close()

		if client == nil {
			t.Fatal("NewClient() returned nil client")
		}
	})

	t.Run("Client with custom timeout", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: container.Address,
			Token:   container.Token,
			Mount:   "pki",
			Timeout: 60 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewClient() failed: %v", err)
		}
		defer client.Close()

		if client.Config().Timeout != 60*time.Second {
			t.Errorf("Timeout = %v, want 60s", client.Config().Timeout)
		}
	})

	t.Run("Client with namespace", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address:   container.Address,
			Token:     container.Token,
			Mount:     "pki",
			Namespace: "test-namespace",
		})
		if err != nil {
			t.Fatalf("NewClient() failed: %v", err)
		}
		defer client.Close()

		if client.Config().Namespace != "test-namespace" {
			t.Errorf("Namespace = %s, want test-namespace", client.Config().Namespace)
		}
	})
}

func TestIntegration_ClientConfig(t *testing.T) {
	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Config returns correct values", func(t *testing.T) {
		cfg := client.Config()
		if cfg == nil {
			t.Fatal("Config() returned nil")
		}

		if cfg.Address != container.Address {
			t.Errorf("Config.Address = %s, want %s", cfg.Address, container.Address)
		}

		if cfg.Token != container.Token {
			t.Errorf("Config.Token = %s, want %s", cfg.Token, container.Token)
		}

		if cfg.Mount != "pki" {
			t.Errorf("Config.Mount = %s, want pki", cfg.Mount)
		}
	})
}

func TestIntegration_ClientClose(t *testing.T) {
	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Close should not error", func(t *testing.T) {
		err := client.Close()
		if err != nil {
			t.Errorf("Close() error = %v, want nil", err)
		}
	})

	t.Run("Close is idempotent", func(t *testing.T) {
		err := client.Close()
		if err != nil {
			t.Errorf("First Close() error = %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("Second Close() error = %v", err)
		}
	})
}

func TestIntegration_ClientHealth(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Health check should pass", func(t *testing.T) {
		err := client.Health(ctx)
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
	})

	t.Run("Health check with context timeout", func(t *testing.T) {
		timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		err := client.Health(timeoutCtx)
		if err != nil {
			t.Fatalf("Health check with timeout failed: %v", err)
		}
	})
}

func TestIntegration_ClientPing(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Ping should work as Health alias", func(t *testing.T) {
		err := client.Ping(ctx)
		if err != nil {
			t.Fatalf("Ping failed: %v", err)
		}
	})

	t.Run("Ping and Health should behave the same", func(t *testing.T) {
		healthErr := client.Health(ctx)
		pingErr := client.Ping(ctx)

		if (healthErr == nil) != (pingErr == nil) {
			t.Errorf("Ping and Health behave differently: Health=%v, Ping=%v", healthErr, pingErr)
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

	t.Run("ValidateConnection should pass with PKI enabled", func(t *testing.T) {
		err := client.ValidateConnection(ctx)
		if err != nil {
			t.Fatalf("ValidateConnection failed: %v", err)
		}
	})

	t.Run("ValidateConnection with wrong mount fails", func(t *testing.T) {
		wrongClient, err := NewClient(&Config{
			Address: container.Address,
			Token:   container.Token,
			Mount:   "nonexistent-mount",
		})
		if err != nil {
			t.Fatalf("NewClient() failed: %v", err)
		}
		defer wrongClient.Close()

		err = wrongClient.ValidateConnection(ctx)
		if err == nil {
			t.Error("ValidateConnection should fail with wrong mount")
		}
		if !IsNotFoundError(err) {
			t.Errorf("Error should be not found error, got: %v", err)
		}
	})

	t.Run("ValidateConnection with wrong token fails", func(t *testing.T) {
		wrongClient, err := NewClient(&Config{
			Address: container.Address,
			Token:   "invalid-token",
			Mount:   "pki",
		})
		if err != nil {
			t.Fatalf("NewClient() failed: %v", err)
		}
		defer wrongClient.Close()

		err = wrongClient.ValidateConnection(ctx)
		if err == nil {
			t.Error("ValidateConnection should fail with wrong token")
		}
		if !IsAuthError(err) {
			t.Errorf("Error should be auth error, got: %v", err)
		}
	})
}

func TestIntegration_ClientSys(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Sys returns valid SDK client", func(t *testing.T) {
		sys := client.Sys()
		if sys == nil {
			t.Fatal("Sys() returned nil")
		}
	})

	t.Run("Can use Sys for operations", func(t *testing.T) {
		sys := client.Sys()

		// Try to list mounts
		mounts, err := sys.ListMountsWithContext(ctx)
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}

		if mounts == nil {
			t.Error("ListMounts returned nil")
		}
	})

	t.Run("Can enable/disable mounts via Sys", func(t *testing.T) {
		sys := client.Sys()

		// Enable a test mount
		err := sys.MountWithContext(ctx, "test-kv", &api.MountInput{
			Type: "kv-v2",
		})
		if err != nil {
			t.Fatalf("Mount failed: %v", err)
		}

		// Verify mount exists
		mounts, err := sys.ListMountsWithContext(ctx)
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}

		if _, exists := mounts["test-kv/"]; !exists {
			t.Error("test-kv mount not found")
		}

		// Cleanup: unmount
		err = sys.UnmountWithContext(ctx, "test-kv")
		if err != nil {
			t.Errorf("Unmount failed: %v", err)
		}
	})
}

func TestIntegration_ClientLogical(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, client := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Logical returns valid SDK client", func(t *testing.T) {
		logical := client.Logical()
		if logical == nil {
			t.Fatal("Logical() returned nil")
		}
	})

	t.Run("Can use Logical for KV operations", func(t *testing.T) {
		// Enable KV
		if err := container.EnableKV(ctx, "secret", 2); err != nil {
			t.Fatalf("EnableKV failed: %v", err)
		}

		logical := client.Logical()

		// Write a secret
		data := map[string]interface{}{
			"data": map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
		}

		_, err := logical.WriteWithContext(ctx, "secret/data/myapp", data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		// Read the secret back
		secret, err := logical.ReadWithContext(ctx, "secret/data/myapp")
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if secret == nil {
			t.Fatal("Read returned nil secret")
		}

		// Verify data
		secretData, ok := secret.Data["data"].(map[string]interface{})
		if !ok {
			t.Fatal("Invalid secret data format")
		}

		if secretData["username"] != "testuser" {
			t.Errorf("username = %v, want testuser", secretData["username"])
		}
	})
}

func TestIntegration_ClientTimeout(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, _ := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	t.Run("Request with very short timeout should fail", func(t *testing.T) {
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
		defer client.Close()

		// Health check should timeout
		timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		err = client.Health(timeoutCtx)
		if err == nil {
			t.Fatal("Expected timeout error, got nil")
		}
	})

	t.Run("Context timeout should be respected", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: container.Address,
			Token:   container.Token,
			Mount:   "pki",
			Timeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		// Create a context that's already cancelled
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		err = client.Health(cancelledCtx)
		if err == nil {
			t.Error("Should fail with cancelled context")
		}
	})
}

func TestIntegration_ClientWithMultipleMounts(t *testing.T) {
	ctx := context.Background()

	// Setup container
	container, _ := setupTestContainer(t)
	defer cleanupTestContainer(t, container)

	// Enable multiple PKI mounts
	if err := container.EnablePKI(ctx, "pki-root", ""); err != nil {
		t.Fatalf("EnablePKI root failed: %v", err)
	}
	if err := container.EnablePKI(ctx, "pki-intermediate", ""); err != nil {
		t.Fatalf("EnablePKI intermediate failed: %v", err)
	}

	t.Run("Client for pki-root", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: container.Address,
			Token:   container.Token,
			Mount:   "pki-root",
		})
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		defer client.Close()

		err = client.ValidateConnection(ctx)
		if err != nil {
			t.Errorf("ValidateConnection for pki-root failed: %v", err)
		}
	})

	t.Run("Client for pki-intermediate", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: container.Address,
			Token:   container.Token,
			Mount:   "pki-intermediate",
		})
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		defer client.Close()

		err = client.ValidateConnection(ctx)
		if err != nil {
			t.Errorf("ValidateConnection for pki-intermediate failed: %v", err)
		}
	})
}
