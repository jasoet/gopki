package transit

import (
	"errors"
	"fmt"
)

// Predefined errors for Transit operations.
// These errors can be used with errors.Is() for error checking.
var (
	// Authentication and authorization errors
	ErrUnauthorized     = errors.New("bao: authentication failed")
	ErrPermissionDenied = errors.New("bao: permission denied")

	// Connection errors
	ErrTimeout           = errors.New("bao: operation timeout")
	ErrHealthCheckFailed = errors.New("bao: health check failed")
	ErrConnectionFailed  = errors.New("bao: connection failed")

	// Mount errors
	ErrMountNotFound = errors.New("bao: transit mount not found")

	// Key errors
	ErrKeyNotFound        = errors.New("bao: key not found")
	ErrKeyVersionNotFound = errors.New("bao: key version not found")
	ErrKeyNotExportable   = errors.New("bao: key is not exportable")
	ErrKeyNotDeletable    = errors.New("bao: key deletion not allowed")
	ErrKeyAlreadyExists   = errors.New("bao: key already exists")

	// Encryption errors
	ErrInvalidCiphertext            = errors.New("bao: invalid ciphertext")
	ErrContextRequired              = errors.New("bao: context required for derived key")
	ErrConvergentEncryptionRequired = errors.New("bao: convergent encryption not enabled")
	ErrInvalidBase64                = errors.New("bao: invalid base64 encoding")

	// Signing errors
	ErrInvalidSignature = errors.New("bao: invalid signature")
	ErrKeyNotSigning    = errors.New("bao: key does not support signing")

	// Batch errors
	ErrBatchTooLarge = errors.New("bao: batch size exceeds maximum")
	ErrEmptyBatch    = errors.New("bao: batch is empty")

	// Configuration errors
	ErrInvalidConfig     = errors.New("bao: invalid configuration")
	ErrMissingAddress    = errors.New("bao: server address is required")
	ErrMissingToken      = errors.New("bao: authentication token is required")
	ErrInvalidBatchSize  = errors.New("bao: invalid batch size")
)

// IsAuthError checks if an error is authentication-related.
func IsAuthError(err error) bool {
	return errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrPermissionDenied)
}

// IsNotFoundError checks if an error is a not-found error.
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrKeyVersionNotFound) ||
		errors.Is(err, ErrMountNotFound)
}

// IsEncryptionError checks if an error is encryption-related.
func IsEncryptionError(err error) bool {
	return errors.Is(err, ErrInvalidCiphertext) ||
		errors.Is(err, ErrContextRequired) ||
		errors.Is(err, ErrConvergentEncryptionRequired) ||
		errors.Is(err, ErrInvalidBase64)
}

// IsBatchError checks if an error is batch operation-related.
func IsBatchError(err error) bool {
	return errors.Is(err, ErrBatchTooLarge) || errors.Is(err, ErrEmptyBatch)
}

// IsConnectionError checks if an error is connection-related.
func IsConnectionError(err error) bool {
	return errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrConnectionFailed) ||
		errors.Is(err, ErrHealthCheckFailed)
}

// WrapError wraps an error with operation context.
// If the error is already a TransitError, it preserves the status code.
func WrapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	var transitErr *TransitError
	if errors.As(err, &transitErr) {
		transitErr.Operation = operation
		return transitErr
	}

	return &TransitError{
		Operation:  operation,
		StatusCode: 0,
		Err:        err,
	}
}

// NewTransitError creates a new TransitError with the given parameters.
func NewTransitError(operation string, statusCode int, errs []string, underlyingErr error) *TransitError {
	return &TransitError{
		Operation:  operation,
		StatusCode: statusCode,
		Errors:     errs,
		Err:        underlyingErr,
	}
}

// ParseResponseError converts an OpenBao API error response to a TransitError.
// This function handles the common error response format from OpenBao.
func ParseResponseError(operation string, statusCode int, errorsField []interface{}) error {
	var errs []string
	for _, e := range errorsField {
		if s, ok := e.(string); ok {
			errs = append(errs, s)
		}
	}

	if len(errs) == 0 {
		errs = []string{fmt.Sprintf("HTTP %d", statusCode)}
	}

	return &TransitError{
		Operation:  operation,
		StatusCode: statusCode,
		Errors:     errs,
	}
}

// CheckStatusCode returns an appropriate error based on the HTTP status code.
func CheckStatusCode(operation string, statusCode int) error {
	switch statusCode {
	case 200, 201, 202, 204:
		return nil
	case 400:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{"bad request"},
		}
	case 401:
		return WrapError(operation, ErrUnauthorized)
	case 403:
		return WrapError(operation, ErrPermissionDenied)
	case 404:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{"not found"},
		}
	case 429:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{"rate limit exceeded"},
		}
	case 500:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{"internal server error"},
		}
	case 502:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{"bad gateway"},
		}
	case 503:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{"service unavailable"},
		}
	default:
		return &TransitError{
			Operation:  operation,
			StatusCode: statusCode,
			Errors:     []string{fmt.Sprintf("unexpected status code: %d", statusCode)},
		}
	}
}
