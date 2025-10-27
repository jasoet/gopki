package vault

import "errors"

// Predefined errors for common Vault operations.
// These can be checked using errors.Is().
var (
	// Client configuration errors
	ErrInvalidConfig    = errors.New("vault: invalid configuration")
	ErrNotConnected     = errors.New("vault: not connected to server")
	ErrUnauthorized     = errors.New("vault: authentication failed")
	ErrPermissionDenied = errors.New("vault: permission denied")
	ErrTimeout          = errors.New("vault: operation timeout")

	// Certificate errors
	ErrCertificateNotFound = errors.New("vault: certificate not found")
	ErrInvalidCSR          = errors.New("vault: invalid certificate request")
	ErrRoleNotFound        = errors.New("vault: role not found")
	ErrCertificateExpired  = errors.New("vault: certificate expired")

	// Key errors
	ErrKeyNotFound     = errors.New("vault: key not found")
	ErrKeyImportFailed = errors.New("vault: key import failed")
	ErrInvalidKeyType  = errors.New("vault: invalid key type")
	ErrKeyExportFailed = errors.New("vault: key export failed")

	// Issuer errors
	ErrIssuerNotFound  = errors.New("vault: issuer not found")
	ErrNoDefaultIssuer = errors.New("vault: no default issuer configured")
	ErrIssuerInvalid   = errors.New("vault: issuer certificate invalid")

	// Connection errors
	ErrHealthCheckFailed = errors.New("vault: health check failed")
	ErrInvalidResponse   = errors.New("vault: invalid response from server")
	ErrRateLimitExceeded = errors.New("vault: rate limit exceeded")
)

// IsRetryable returns true if the error is retryable.
// Retryable errors are typically transient network issues or 5xx server errors.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific retryable errors
	if errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrHealthCheckFailed) ||
		errors.Is(err, ErrNotConnected) {
		return true
	}

	// Check for VaultError with retryable status codes
	var vaultErr *VaultError
	if errors.As(err, &vaultErr) {
		// 5xx errors are retryable
		return vaultErr.StatusCode >= 500 && vaultErr.StatusCode < 600
	}

	return false
}

// IsAuthError returns true if the error is an authentication error.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrPermissionDenied) {
		return true
	}

	var vaultErr *VaultError
	if errors.As(err, &vaultErr) {
		return vaultErr.StatusCode == 401 || vaultErr.StatusCode == 403
	}

	return false
}

// IsNotFoundError returns true if the error indicates a resource was not found.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrCertificateNotFound) ||
		errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrIssuerNotFound) ||
		errors.Is(err, ErrRoleNotFound) {
		return true
	}

	var vaultErr *VaultError
	if errors.As(err, &vaultErr) {
		return vaultErr.StatusCode == 404
	}

	return false
}
