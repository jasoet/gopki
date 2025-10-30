package transit

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Config holds the configuration for the Transit client.
type Config struct {
	// Address is the OpenBao server URL (required).
	// Example: "https://openbao.example.com:8200"
	Address string

	// Token is the authentication token for OpenBao (required).
	Token string

	// Namespace is the OpenBao namespace (optional, Enterprise feature).
	// Example: "admin/dev"
	Namespace string

	// Mount is the Transit secrets engine mount path (default: "transit").
	Mount string

	// TLSConfig is the TLS configuration for HTTPS connections (optional).
	// If nil, the default TLS configuration will be used.
	TLSConfig *tls.Config

	// HTTPClient is a custom HTTP client (optional).
	// If nil, a default client will be created with appropriate timeouts.
	HTTPClient *http.Client

	// Timeout is the request timeout duration (default: 30s).
	// This applies to individual API requests.
	Timeout time.Duration

	// RetryConfig configures retry behavior for failed requests (optional).
	// If nil, a default retry configuration will be used.
	RetryConfig *RetryConfig

	// MaxBatchSize limits the number of items in a batch operation (default: 250).
	// This is based on OpenBao's max_request_json_strings limit.
	// Maximum allowed value is AbsoluteMaxBatchSize (1000).
	MaxBatchSize int

	// Cache configures optional caching for key metadata (optional, opt-in).
	// If nil, caching is disabled by default.
	Cache *CacheConfig
}

// RetryConfig configures retry behavior for failed requests.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (default: 3).
	MaxRetries int

	// BaseDelay is the initial delay between retries (default: 1s).
	BaseDelay time.Duration

	// MaxDelay is the maximum delay between retries (default: 30s).
	MaxDelay time.Duration

	// Multiplier is the backoff multiplier (default: 2.0).
	// Each retry delay is calculated as: min(BaseDelay * (Multiplier ^ attempt), MaxDelay)
	Multiplier float64
}

// CacheConfig configures optional caching for key metadata.
// Caching is DISABLED by default and must be explicitly enabled.
type CacheConfig struct {
	// Enabled determines whether caching is active (default: false).
	// Must be explicitly set to true to enable caching.
	Enabled bool

	// TTL is the cache time-to-live duration (default: 5 minutes).
	// Cached key information expires after this duration.
	TTL time.Duration
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

// DefaultCacheConfig returns the default cache configuration.
// Note: Caching is disabled by default (Enabled: false).
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled: false,
		TTL:     5 * time.Minute,
	}
}

// Validate validates the configuration and sets defaults.
func (c *Config) Validate() error {
	// Required fields
	if c.Address == "" {
		return fmt.Errorf("%w: address", ErrInvalidConfig)
	}
	if c.Token == "" {
		return fmt.Errorf("%w: token", ErrInvalidConfig)
	}

	// Set defaults for optional fields
	if c.Mount == "" {
		c.Mount = "transit"
	}

	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}

	if c.RetryConfig == nil {
		c.RetryConfig = DefaultRetryConfig()
	}

	// Validate retry config
	if err := c.RetryConfig.Validate(); err != nil {
		return fmt.Errorf("invalid retry config: %w", err)
	}

	// Set default batch size
	if c.MaxBatchSize == 0 {
		c.MaxBatchSize = DefaultMaxBatchSize
	}

	// Warn if batch size exceeds recommended limit
	// In production, this would use a logger
	if c.MaxBatchSize > DefaultMaxBatchSize && c.MaxBatchSize <= AbsoluteMaxBatchSize {
		// Log warning: MaxBatchSize exceeds recommended limit
		// Ensure your OpenBao server is configured with higher limits
	}

	// Enforce absolute maximum
	if c.MaxBatchSize > AbsoluteMaxBatchSize {
		return fmt.Errorf("%w: MaxBatchSize %d exceeds absolute maximum %d",
			ErrInvalidBatchSize, c.MaxBatchSize, AbsoluteMaxBatchSize)
	}

	if c.MaxBatchSize < 1 {
		return fmt.Errorf("%w: MaxBatchSize must be at least 1", ErrInvalidBatchSize)
	}

	// Validate cache config if provided
	if c.Cache != nil {
		if err := c.Cache.Validate(); err != nil {
			return fmt.Errorf("invalid cache config: %w", err)
		}
	}

	// Validate TLS config if HTTPS is used
	if c.TLSConfig != nil && c.TLSConfig.InsecureSkipVerify {
		// In production, this should log a warning
		// Skipping TLS verification is insecure and should not be used in production
	}

	return nil
}

// Validate validates the retry configuration.
func (rc *RetryConfig) Validate() error {
	if rc.MaxRetries < 0 {
		return fmt.Errorf("MaxRetries must be >= 0, got %d", rc.MaxRetries)
	}

	if rc.BaseDelay < 0 {
		return fmt.Errorf("BaseDelay must be >= 0, got %v", rc.BaseDelay)
	}

	if rc.MaxDelay < rc.BaseDelay {
		return fmt.Errorf("MaxDelay (%v) must be >= BaseDelay (%v)", rc.MaxDelay, rc.BaseDelay)
	}

	if rc.Multiplier < 1.0 {
		return fmt.Errorf("Multiplier must be >= 1.0, got %f", rc.Multiplier)
	}

	return nil
}

// Validate validates the cache configuration.
func (cc *CacheConfig) Validate() error {
	if cc.Enabled && cc.TTL <= 0 {
		return fmt.Errorf("cache TTL must be > 0 when caching is enabled, got %v", cc.TTL)
	}

	return nil
}

// Clone creates a deep copy of the configuration.
// This is useful for creating multiple clients with slightly different configurations.
func (c *Config) Clone() *Config {
	clone := &Config{
		Address:      c.Address,
		Token:        c.Token,
		Namespace:    c.Namespace,
		Mount:        c.Mount,
		Timeout:      c.Timeout,
		MaxBatchSize: c.MaxBatchSize,
	}

	// Clone TLS config
	if c.TLSConfig != nil {
		clone.TLSConfig = c.TLSConfig.Clone()
	}

	// Clone HTTP client (note: this is a shallow copy)
	if c.HTTPClient != nil {
		clone.HTTPClient = c.HTTPClient
	}

	// Clone retry config
	if c.RetryConfig != nil {
		retryClone := *c.RetryConfig
		clone.RetryConfig = &retryClone
	}

	// Clone cache config
	if c.Cache != nil {
		cacheClone := *c.Cache
		clone.Cache = &cacheClone
	}

	return clone
}
