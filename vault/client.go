package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/api/v2"
)

// Health checks the health status of the Vault server.
// This performs a basic health check without requiring authentication.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	if err := client.Health(ctx); err != nil {
//	    log.Printf("Vault unhealthy: %v", err)
//	}
func (c *Client) Health(ctx context.Context) error {
	// Use SDK's Health API
	healthResp, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("vault: health check timeout: %w", ErrTimeout)
			}
			return fmt.Errorf("vault: health check cancelled: %w", ctx.Err())
		}
		return fmt.Errorf("vault: health check failed: %w", ErrHealthCheckFailed)
	}

	// Check if Vault is initialized and unsealed
	if !healthResp.Initialized {
		return fmt.Errorf("vault: not initialized: %w", ErrHealthCheckFailed)
	}
	if healthResp.Sealed {
		return fmt.Errorf("vault: sealed: %w", ErrHealthCheckFailed)
	}

	return nil
}

// ValidateConnection validates that the client can successfully connect to Vault
// and authenticate. This checks both connectivity and authentication.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	if err := client.ValidateConnection(ctx); err != nil {
//	    log.Fatalf("Cannot connect to Vault: %v", err)
//	}
func (c *Client) ValidateConnection(ctx context.Context) error {
	// First check health
	if err := c.Health(ctx); err != nil {
		return fmt.Errorf("vault: connection validation: %w", err)
	}

	// Try to read PKI mount config to verify authentication and mount access
	path := fmt.Sprintf("%s/config/urls", c.config.Mount)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		// Check if it's a permission or auth error
		if apiErr, ok := err.(*api.ResponseError); ok {
			switch apiErr.StatusCode {
			case 401:
				return fmt.Errorf("vault: unauthorized: %w", ErrUnauthorized)
			case 403:
				return fmt.Errorf("vault: permission denied for mount '%s': %w", c.config.Mount, ErrPermissionDenied)
			case 404:
				return fmt.Errorf("vault: PKI mount '%s' not found: %w", c.config.Mount, ErrMountNotFound)
			}
		}
		return fmt.Errorf("vault: connection validation: %w", err)
	}

	// SDK returns nil secret and nil error for 404
	// We need to verify the mount actually exists by checking for valid response
	// For PKI mounts, config/urls should always return something (even if empty data)
	// If secret is nil, the mount likely doesn't exist
	if secret == nil {
		return fmt.Errorf("vault: PKI mount '%s' not found: %w", c.config.Mount, ErrMountNotFound)
	}

	return nil
}

// Ping is an alias for Health for compatibility.
func (c *Client) Ping(ctx context.Context) error {
	return c.Health(ctx)
}

// Sys returns the underlying OpenBao SDK Sys client for advanced operations.
// This is exposed for integration testing and advanced use cases.
func (c *Client) Sys() *api.Sys {
	return c.client.Sys()
}

// Logical returns the SDK's Logical client for low-level API access.
// This allows advanced users to make custom API calls.
func (c *Client) Logical() *api.Logical {
	return c.client.Logical()
}
