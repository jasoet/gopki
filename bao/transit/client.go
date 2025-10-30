package transit

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/api/v2"
)

// Client is the main client for OpenBao Transit operations.
// It provides methods for key management, encryption, signing, and other
// cryptographic operations.
//
// Example usage:
//
//	config := &transit.Config{
//	    Address: "https://openbao.example.com",
//	    Token:   token,
//	}
//
//	client, err := transit.NewClient(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Create and use a key
//	keyClient, err := client.CreateAES256Key(ctx, "my-key", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
type Client struct {
	config *Config
	client *api.Client
	// middleware *MiddlewareChain // TODO: Phase 8
	// cache      *KeyCache        // TODO: Phase 8
}

// NewClient creates a new Transit client with the given configuration.
// The configuration is validated before creating the client.
//
// Example:
//
//	config := &transit.Config{
//	    Address: "https://openbao.example.com",
//	    Token:   token,
//	    Mount:   "transit",
//	}
//
//	client, err := transit.NewClient(config)
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfig)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create OpenBao API client configuration
	apiConfig := api.DefaultConfig()
	apiConfig.Address = config.Address

	// Set timeout
	if config.Timeout > 0 {
		apiConfig.Timeout = config.Timeout
	}

	// Set TLS configuration
	if config.TLSConfig != nil {
		if err := apiConfig.ConfigureTLS(&api.TLSConfig{
			ClientCert: "",
			ClientKey:  "",
			CACert:     "",
			Insecure:   config.TLSConfig.InsecureSkipVerify,
			TLSServerName: config.TLSConfig.ServerName,
		}); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}

	// Use custom HTTP client if provided
	if config.HTTPClient != nil {
		apiConfig.HttpClient = config.HTTPClient
	}

	// Create OpenBao client
	apiClient, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("create API client: %w", err)
	}

	// Set token
	apiClient.SetToken(config.Token)

	// Set namespace if provided (Enterprise feature)
	if config.Namespace != "" {
		apiClient.SetNamespace(config.Namespace)
	}

	client := &Client{
		config: config,
		client: apiClient,
	}

	// TODO: Phase 8 - Initialize middleware chain
	// client.middleware = NewMiddlewareChain()

	// TODO: Phase 8 - Initialize cache if enabled
	// if config.Cache != nil && config.Cache.Enabled {
	//     client.cache = NewKeyCache(config.Cache)
	// }

	return client, nil
}

// Config returns the client's configuration.
// The returned configuration should not be modified.
func (c *Client) Config() *Config {
	return c.config
}

// Close cleans up the client resources.
// This method should be called when the client is no longer needed.
func (c *Client) Close() error {
	// Currently nothing to clean up, but this provides
	// a hook for future resource cleanup
	return nil
}

// Health performs a health check on the OpenBao server.
// Returns nil if the server is healthy and reachable.
//
// Example:
//
//	if err := client.Health(ctx); err != nil {
//	    log.Printf("Health check failed: %v", err)
//	}
func (c *Client) Health(ctx context.Context) error {
	resp, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return WrapError("Health", err)
	}

	if !resp.Initialized {
		return &TransitError{
			Operation:  "Health",
			StatusCode: 0,
			Errors:     []string{"OpenBao is not initialized"},
		}
	}

	if resp.Sealed {
		return &TransitError{
			Operation:  "Health",
			StatusCode: 0,
			Errors:     []string{"OpenBao is sealed"},
		}
	}

	return nil
}

// Ping is an alias for Health.
// It performs a health check on the OpenBao server.
func (c *Client) Ping(ctx context.Context) error {
	return c.Health(ctx)
}

// ValidateConnection validates the connection to OpenBao and verifies
// that the Transit mount exists and is accessible.
//
// This method checks:
//   - Server is healthy and unsealed
//   - Authentication token is valid
//   - Transit mount exists and is accessible
//
// Example:
//
//	if err := client.ValidateConnection(ctx); err != nil {
//	    log.Fatalf("Connection validation failed: %v", err)
//	}
func (c *Client) ValidateConnection(ctx context.Context) error {
	// 1. Check server health
	if err := c.Health(ctx); err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	// 2. Verify authentication by checking token info
	secret, err := c.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return WrapError("ValidateConnection", ErrUnauthorized)
	}

	if secret == nil || secret.Data == nil {
		return WrapError("ValidateConnection", ErrUnauthorized)
	}

	// 3. Verify Transit mount exists
	mounts, err := c.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return WrapError("ValidateConnection", err)
	}

	mountPath := c.config.Mount + "/"
	found := false
	for path, mount := range mounts {
		if path == mountPath && mount.Type == "transit" {
			found = true
			break
		}
	}

	if !found {
		return WrapError("ValidateConnection", ErrMountNotFound)
	}

	return nil
}

// Sys returns the underlying OpenBao system API client.
// This provides access to low-level system operations.
//
// Use this for operations not directly supported by the Transit client,
// such as mount management or policy operations.
func (c *Client) Sys() *api.Sys {
	return c.client.Sys()
}

// Logical returns the underlying OpenBao logical API client.
// This provides access to low-level logical operations.
//
// Use this for advanced operations not directly supported by the Transit client.
func (c *Client) Logical() *api.Logical {
	return c.client.Logical()
}

// buildPath constructs the full path for a Transit API endpoint.
func (c *Client) buildPath(endpoint string) string {
	return fmt.Sprintf("%s/%s", c.config.Mount, endpoint)
}

// read performs a read operation on the Transit API.
func (c *Client) read(ctx context.Context, path string) (*api.Secret, error) {
	fullPath := c.buildPath(path)
	secret, err := c.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// write performs a write operation on the Transit API.
func (c *Client) write(ctx context.Context, path string, data map[string]interface{}) (*api.Secret, error) {
	fullPath := c.buildPath(path)
	secret, err := c.client.Logical().WriteWithContext(ctx, fullPath, data)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// delete performs a delete operation on the Transit API.
func (c *Client) delete(ctx context.Context, path string) (*api.Secret, error) {
	fullPath := c.buildPath(path)
	secret, err := c.client.Logical().DeleteWithContext(ctx, fullPath)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// list performs a list operation on the Transit API.
func (c *Client) list(ctx context.Context, path string) (*api.Secret, error) {
	fullPath := c.buildPath(path)
	secret, err := c.client.Logical().ListWithContext(ctx, fullPath)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// HTTPClient returns the underlying HTTP client used for API requests.
// This can be used to inspect or modify HTTP client settings.
func (c *Client) HTTPClient() *http.Client {
	return c.client.CloneConfig().HttpClient
}

// SetToken updates the authentication token.
// This is useful for token rotation without creating a new client.
func (c *Client) SetToken(token string) {
	c.client.SetToken(token)
	c.config.Token = token
}

// SetNamespace updates the namespace for Enterprise OpenBao.
// This is useful for switching between namespaces without creating a new client.
func (c *Client) SetNamespace(namespace string) {
	c.client.SetNamespace(namespace)
	c.config.Namespace = namespace
}
