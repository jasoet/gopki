package pki

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Config contains configuration for connecting to OpenBao.
type Config struct {
	// Address is the OpenBao server URL (required)
	// Example: "https://openbao.example.com"
	Address string

	// Token is the OpenBao authentication token (required)
	// Example: "hvs.CAESIHNPbm..."
	// Security: Store securely, use environment variables
	Token string

	// Namespace is the OpenBao namespace (optional, Enterprise only)
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
		return fmt.Errorf("bao: address is required")
	}

	if c.Token == "" {
		return fmt.Errorf("bao: token is required")
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(c.Address)
	if err != nil {
		return fmt.Errorf("bao: invalid address: %w", err)
	}

	// Check scheme
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("bao: address must use http or https scheme")
	}

	// Warn about insecure connections
	if parsedURL.Scheme == "http" {
		// Log warning (will be implemented with actual logging)
		// log.Warn("bao: using insecure HTTP connection")
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
