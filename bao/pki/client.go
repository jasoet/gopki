package pki

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/api/v2"
)

// Client represents an OpenBao PKI client.
type Client struct {
	config *Config
	client *api.Client // OpenBao SDK client
}

// NewClient creates a new OpenBao client using the OpenBao SDK.
// The client validates the configuration and establishes connection settings.
//
// Example:
//
//	client, err := bao.NewClient(&bao.Config{
//	    Address: "https://openbao.example.com",
//	    Token:   os.Getenv("BAO_TOKEN"),
//	    Mount:   "pki",
//	})
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("bao: config is required")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create OpenBao SDK config
	apiConfig := api.DefaultConfig()
	apiConfig.Address = config.Address

	// Configure TLS if provided
	if config.TLSConfig != nil {
		tlsConfig := &api.TLSConfig{
			CACert:        "",
			CAPath:        "",
			ClientCert:    "",
			ClientKey:     "",
			TLSServerName: "",
			Insecure:      config.TLSConfig.InsecureSkipVerify,
		}
		if err := apiConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("bao: configure TLS: %w", err)
		}
	}

	// Set timeout
	if config.Timeout > 0 {
		apiConfig.Timeout = config.Timeout
	}

	// Create HTTP client if provided (for custom transport)
	if config.HTTPClient != nil {
		apiConfig.HttpClient = config.HTTPClient
	}

	// Create OpenBao SDK client
	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("bao: create SDK client: %w", err)
	}

	// Set authentication token
	client.SetToken(config.Token)

	// Set namespace if provided
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	return &Client{
		config: config,
		client: client,
	}, nil
}

// Config returns the client configuration.
func (c *Client) Config() *Config {
	return c.config
}

// Close closes the client and releases resources.
// This is a no-op for HTTP clients but included for future extensibility.
func (c *Client) Close() error {
	// Future: close persistent connections if needed
	return nil
}

// Health checks the health status of the OpenBao server.
// This performs a basic health check without requiring authentication.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	if err := client.Health(ctx); err != nil {
//	    log.Printf("OpenBao unhealthy: %v", err)
//	}
func (c *Client) Health(ctx context.Context) error {
	// Use SDK's Health API
	healthResp, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("bao: health check timeout: %w", ErrTimeout)
			}
			return fmt.Errorf("bao: health check cancelled: %w", ctx.Err())
		}
		return fmt.Errorf("bao: health check failed: %w", ErrHealthCheckFailed)
	}

	// Check if OpenBao is initialized and unsealed
	if !healthResp.Initialized {
		return fmt.Errorf("bao: not initialized: %w", ErrHealthCheckFailed)
	}
	if healthResp.Sealed {
		return fmt.Errorf("bao: sealed: %w", ErrHealthCheckFailed)
	}

	return nil
}

// ValidateConnection validates that the client can successfully connect to OpenBao
// and authenticate. This checks both connectivity and authentication.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	if err := client.ValidateConnection(ctx); err != nil {
//	    log.Fatalf("Cannot connect to OpenBao: %v", err)
//	}
func (c *Client) ValidateConnection(ctx context.Context) error {
	// First check health
	if err := c.Health(ctx); err != nil {
		return fmt.Errorf("bao: connection validation: %w", err)
	}

	// Try to read PKI mount config to verify authentication and mount access
	path := fmt.Sprintf("%s/config/urls", c.config.Mount)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		// Check if it's a permission or auth error
		if apiErr, ok := err.(*api.ResponseError); ok {
			switch apiErr.StatusCode {
			case 401:
				return fmt.Errorf("bao: unauthorized: %w", ErrUnauthorized)
			case 403:
				return fmt.Errorf("bao: permission denied for mount '%s': %w", c.config.Mount, ErrPermissionDenied)
			case 404:
				return fmt.Errorf("bao: PKI mount '%s' not found: %w", c.config.Mount, ErrMountNotFound)
			}
		}
		return fmt.Errorf("bao: connection validation: %w", err)
	}

	// OpenBao SDK quirk: returns (nil secret, nil error) for non-existent paths
	// instead of (nil, 404 error). We validate the mount exists by checking
	// for a non-nil response. PKI mounts should always return a response for
	// config/urls endpoint, even with empty data.
	if secret == nil {
		return fmt.Errorf("bao: PKI mount '%s' not found or inaccessible: %w", c.config.Mount, ErrMountNotFound)
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
