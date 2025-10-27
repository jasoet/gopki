package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// doRequest performs an HTTP request with Vault authentication and error handling.
// It handles authentication headers, response parsing, and error wrapping.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	// Build full URL
	fullURL := c.buildURL(path)

	// Marshal body if provided
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("vault: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("vault: create request: %w", err)
	}

	// Add authentication and headers
	c.addAuthHeaders(req)

	// Set content type for requests with body
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Check for context errors
		if ctx.Err() != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("vault: request timeout: %w", ErrTimeout)
			}
			return nil, fmt.Errorf("vault: request cancelled: %w", ctx.Err())
		}
		return nil, fmt.Errorf("vault: request failed: %w", err)
	}

	return resp, nil
}

// buildURL constructs the full URL for a Vault API path.
func (c *Client) buildURL(path string) string {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Build URL with baseURL
	u := *c.baseURL
	u.Path = path

	return u.String()
}

// addAuthHeaders adds Vault authentication headers to the request.
func (c *Client) addAuthHeaders(req *http.Request) {
	// Add Vault token
	req.Header.Set("X-Vault-Token", c.config.Token)

	// Add namespace if configured (Vault Enterprise)
	if c.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.config.Namespace)
	}

	// Add user agent
	req.Header.Set("User-Agent", "gopki-vault/1.0")
}

// parseResponse parses a JSON response from Vault into the target struct.
// It handles error responses and wraps them in VaultError.
func (c *Client) parseResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("vault: read response: %w", err)
	}

	// Check for error responses
	if resp.StatusCode >= 400 {
		return c.parseErrorResponse(resp, body)
	}

	// Parse successful response
	if target != nil && len(body) > 0 {
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("vault: parse response: %w", err)
		}
	}

	return nil
}

// parseErrorResponse parses an error response from Vault.
func (c *Client) parseErrorResponse(resp *http.Response, body []byte) error {
	// Try to parse as Vault error format
	var vaultResp struct {
		Errors []string `json:"errors"`
	}

	var errors []string
	if json.Unmarshal(body, &vaultResp) == nil && len(vaultResp.Errors) > 0 {
		errors = vaultResp.Errors
	}

	// Determine the base error
	var baseErr error
	switch resp.StatusCode {
	case 401:
		baseErr = ErrUnauthorized
	case 403:
		baseErr = ErrPermissionDenied
	case 404:
		baseErr = ErrCertificateNotFound // Generic not found
	case 429:
		baseErr = ErrRateLimitExceeded
	}

	return &VaultError{
		Operation:  "request",
		StatusCode: resp.StatusCode,
		Errors:     errors,
		Err:        baseErr,
	}
}

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
	// Use sys/health endpoint (no auth required)
	req, err := http.NewRequestWithContext(ctx, "GET", c.buildURL("/v1/sys/health"), nil)
	if err != nil {
		return fmt.Errorf("vault: create health request: %w", err)
	}

	// Don't add auth headers for health check
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("vault: health check timeout: %w", ErrTimeout)
			}
			return fmt.Errorf("vault: health check cancelled: %w", ctx.Err())
		}
		return fmt.Errorf("vault: health check failed: %w", ErrHealthCheckFailed)
	}
	defer resp.Body.Close()

	// Vault health endpoint returns:
	// 200 - initialized, unsealed, active
	// 429 - unsealed, standby
	// 472 - disaster recovery mode
	// 473 - performance standby
	// 501 - not initialized
	// 503 - sealed

	// Accept 200, 429, 472, 473 as healthy
	switch resp.StatusCode {
	case 200, 429, 472, 473:
		return nil
	case 501:
		return fmt.Errorf("vault: not initialized: %w", ErrHealthCheckFailed)
	case 503:
		return fmt.Errorf("vault: sealed: %w", ErrHealthCheckFailed)
	default:
		return fmt.Errorf("vault: unhealthy (status %d): %w", resp.StatusCode, ErrHealthCheckFailed)
	}
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

	// Try to read PKI mount to verify authentication and mount access
	path := fmt.Sprintf("/v1/%s/config/urls", c.config.Mount)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return fmt.Errorf("vault: connection validation: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)

		// Parse error response to create VaultError
		err := c.parseErrorResponse(resp, body)

		// Add mount context to the error
		if resp.StatusCode == 404 {
			return fmt.Errorf("vault: PKI mount '%s' not found: %w", c.config.Mount, err)
		}
		if resp.StatusCode == 403 {
			return fmt.Errorf("vault: permission denied for mount '%s': %w", c.config.Mount, err)
		}

		return fmt.Errorf("vault: connection validation failed: %w", err)
	}

	return nil
}

// Ping is an alias for Health for compatibility.
func (c *Client) Ping(ctx context.Context) error {
	return c.Health(ctx)
}
