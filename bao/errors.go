package bao

import "errors"

// Predefined errors for common OpenBao operations.
// These can be checked using errors.Is().
var (
	// Authentication and authorization errors
	ErrUnauthorized     = errors.New("bao: authentication failed")
	ErrPermissionDenied = errors.New("bao: permission denied")

	// Connection errors
	ErrTimeout           = errors.New("bao: operation timeout")
	ErrHealthCheckFailed = errors.New("bao: health check failed")

	// Mount errors
	ErrMountNotFound = errors.New("bao: PKI mount not found")
)

// IsAuthError returns true if the error is an authentication error.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrPermissionDenied)
}

// IsNotFoundError returns true if the error indicates a resource was not found.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrMountNotFound)
}
