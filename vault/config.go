package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// Config contains configuration for connecting to Vault/OpenBao.
type Config struct {
	// Address is the Vault/OpenBao server URL (required)
	// Example: "https://vault.example.com"
	Address string

	// Token is the Vault authentication token (required)
	// Example: "hvs.CAESIHNPbm..."
	// Security: Store securely, use environment variables
	Token string

	// Namespace is the Vault namespace (optional, Enterprise only)
	// Example: "admin/engineering"
	Namespace string

	// Mount is the PKI secrets engine mount path (default: "pki")
	// Example: "pki", "pki-root", "pki-intermediate"
	Mount string

	// TLSConfig for HTTPS connections (optional)
	// If nil, uses default TLS configuration
	TLSConfig *tls.Config

	// HTTPClient allows providing a custom HTTP client (optional)
	// If nil, creates a new client with TLSConfig
	HTTPClient *http.Client

	// Timeout for HTTP requests (default: 30 seconds)
	// Applied to individual requests
	Timeout time.Duration

	// RetryConfig for failed requests (optional)
	// If nil, no retries are performed
	RetryConfig *RetryConfig
}

// RetryConfig contains configuration for retrying failed requests.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts
	// Default: 3
	MaxRetries int

	// BaseDelay is the initial delay between retries
	// Default: 1 second
	BaseDelay time.Duration

	// MaxDelay is the maximum delay between retries
	// Default: 30 seconds
	MaxDelay time.Duration

	// Multiplier is the backoff multiplier for exponential backoff
	// Default: 2.0
	Multiplier float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries: 3,
		BaseDelay:  1 * time.Second,
		MaxDelay:   30 * time.Second,
		Multiplier: 2.0,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("vault: address is required")
	}

	if c.Token == "" {
		return fmt.Errorf("vault: token is required")
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(c.Address)
	if err != nil {
		return fmt.Errorf("vault: invalid address: %w", err)
	}

	// Check scheme
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("vault: address must use http or https scheme")
	}

	// Warn about insecure connections
	if parsedURL.Scheme == "http" {
		// Log warning (will be implemented with actual logging)
		// log.Warn("vault: using insecure HTTP connection")
	}

	// Set defaults
	if c.Mount == "" {
		c.Mount = "pki"
	}

	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}

	return nil
}

// Client represents a Vault/OpenBao PKI client.
type Client struct {
	config     *Config
	client     *api.Client  // OpenBao SDK client
	httpClient *http.Client // Kept for backward compatibility
	baseURL    *url.URL     // Kept for backward compatibility
}

// NewClient creates a new Vault/OpenBao client using the OpenBao SDK.
// The client validates the configuration and establishes connection settings.
//
// Example:
//
//	client, err := vault.NewClient(&vault.Config{
//	    Address: "https://vault.example.com",
//	    Token:   os.Getenv("VAULT_TOKEN"),
//	    Mount:   "pki",
//	})
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("vault: config is required")
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
			return nil, fmt.Errorf("vault: configure TLS: %w", err)
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
		return nil, fmt.Errorf("vault: create SDK client: %w", err)
	}

	// Set authentication token
	client.SetToken(config.Token)

	// Set namespace if provided
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	// Parse base URL (kept for backward compatibility)
	baseURL, err := url.Parse(config.Address)
	if err != nil {
		return nil, fmt.Errorf("vault: parse address: %w", err)
	}

	return &Client{
		config:     config,
		client:     client,
		httpClient: apiConfig.HttpClient,
		baseURL:    baseURL,
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
