// Package format provides utilities for cryptographic key format detection, conversion,
// and management. It supports multiple key formats including PEM, DER, and SSH formats
// with automatic format detection capabilities.
//
// Supported formats:
//   - PEM: Base64 encoded keys with headers (most common, human-readable)
//   - DER: Binary encoded keys (compact, faster parsing)
//   - SSH: OpenSSH key formats (both public key and private key formats)
//
// The package provides format conversion between these formats and includes
// robust error handling with detailed error information.
package format

import (
	"fmt"
	"strings"
)

// KeyFormat represents the encoding format of a cryptographic key.
// Each format has different characteristics suitable for different use cases.
type KeyFormat int

const (
	// FormatPEM represents the PEM (Privacy-Enhanced Mail) format.
	// PEM uses Base64 encoding with headers, making it human-readable and widely supported.
	FormatPEM KeyFormat = iota

	// FormatDER represents the DER (Distinguished Encoding Rules) format.
	// DER is a binary format that is more compact and faster to parse than PEM.
	FormatDER

	// FormatSSH represents OpenSSH key formats.
	// Includes both public key format (ssh-rsa, ssh-ed25519, etc.) and OpenSSH private key format.
	FormatSSH

	// FormatAuto indicates automatic format detection should be used.
	// This is used when the format is unknown and needs to be detected from the data.
	FormatAuto
)

// String returns the string representation of the KeyFormat.
// This method implements the fmt.Stringer interface for better debugging and logging.
//
// Returns:
//   - String name of the format ("PEM", "DER", "SSH", "AUTO", or "UNKNOWN")
func (f KeyFormat) String() string {
	switch f {
	case FormatPEM:
		return "PEM"
	case FormatDER:
		return "DER"
	case FormatSSH:
		return "SSH"
	case FormatAuto:
		return "AUTO"
	default:
		return "UNKNOWN"
	}
}

// EncodedKey represents a cryptographic key in a specific encoding format.
// It contains the key data along with metadata about the format and key type.
type EncodedKey struct {
	Data    []byte    // The encoded key data in the specified format
	Format  KeyFormat // The format of the encoded data (PEM, DER, SSH)
	Comment string    // Optional comment (primarily used for SSH public keys)
	KeyType string    // Key algorithm type ("RSA", "ECDSA", "Ed25519")
}

// EncodedKeyPair represents a pair of encoded cryptographic keys (private and public).
// Both keys may be in different formats depending on the use case.
type EncodedKeyPair struct {
	Private *EncodedKey // The encoded private key
	Public  *EncodedKey // The encoded public key
}

// FormatError represents an error that occurred during key format operations.
// It provides detailed context about which format caused the error and the underlying cause.
type FormatError struct {
	Format  KeyFormat // The format that caused the error
	Message string    // Descriptive error message
	Cause   error     // The underlying error that caused this format error
}

// Error implements the error interface for FormatError.
// It provides a formatted error message that includes the format and optional cause.
//
// Returns:
//   - A formatted error string with format context and underlying cause (if any)
func (e *FormatError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s format error: %s: %v", e.Format, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s format error: %s", e.Format, e.Message)
}

// Unwrap returns the underlying error that caused this FormatError.
// This method supports Go 1.13+ error unwrapping for error chain traversal.
//
// Returns:
//   - The underlying error, or nil if there is no underlying error
func (e *FormatError) Unwrap() error {
	return e.Cause
}

// NewFormatError creates a new FormatError with the specified format, message, and optional cause.
// This is the preferred way to create format-related errors throughout the package.
//
// Parameters:
//   - format: The format that caused the error
//   - message: Descriptive error message
//   - cause: Optional underlying error that caused this error
//
// Returns:
//   - A new FormatError instance
//
// Example:
//
//	err := NewFormatError(FormatPEM, "invalid PEM header", originalErr)
func NewFormatError(format KeyFormat, message string, cause error) *FormatError {
	return &FormatError{
		Format:  format,
		Message: message,
		Cause:   cause,
	}
}

// DetectFormat automatically detects the format of key data by examining its content.
// It uses heuristics to identify PEM, DER, and SSH formats based on content patterns.
//
// Detection logic:
//   - SSH private keys: Look for "-----BEGIN OPENSSH PRIVATE KEY-----" header
//   - PEM format: Look for "-----BEGIN" header
//   - SSH public keys: Look for "ssh-rsa", "ssh-ed25519", or "ecdsa-sha2-" prefixes
//   - DER format: Binary data that is not printable text and sufficiently long
//
// Parameters:
//   - data: The key data to analyze
//
// Returns:
//   - KeyFormat: The detected format (or FormatAuto if detection fails)
//   - error: Error if data is empty or format cannot be determined
//
// Example:
//
//	format, err := DetectFormat(keyData)
//	if err != nil {
//		log.Printf("Could not detect format: %v", err)
//	}
func DetectFormat(data []byte) (KeyFormat, error) {
	if len(data) == 0 {
		return FormatAuto, NewFormatError(FormatAuto, "empty data", nil)
	}

	dataStr := string(data)

	if strings.Contains(dataStr, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return FormatSSH, nil
	}

	if strings.HasPrefix(dataStr, "-----BEGIN") {
		return FormatPEM, nil
	}

	if strings.HasPrefix(dataStr, "ssh-rsa ") ||
		strings.HasPrefix(dataStr, "ssh-ed25519 ") ||
		strings.HasPrefix(dataStr, "ecdsa-sha2-") {
		return FormatSSH, nil
	}

	if !isPrintableText(data) && len(data) > 50 {
		return FormatDER, nil
	}

	return FormatAuto, NewFormatError(FormatAuto, "unable to detect format", nil)
}

// isPrintableText determines if the given data consists primarily of printable text.
// This is used as a heuristic to distinguish between text-based formats (PEM, SSH) and binary formats (DER).
//
// The function considers data printable if at least 95% of bytes are:
//   - ASCII printable characters (32-126)
//   - Common whitespace characters (newline, carriage return, tab)
//
// Parameters:
//   - data: The data to analyze
//
// Returns:
//   - true if the data is primarily printable text, false otherwise
func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printableCount := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}

	return float64(printableCount)/float64(len(data)) > 0.95
}

// ValidateFormat checks if a given format is supported for a specific operation.
// This function is used to validate format compatibility before attempting conversions.
//
// Parameters:
//   - format: The format to validate
//   - supportedFormats: List of formats supported by the operation
//
// Returns:
//   - nil if the format is supported
//   - FormatError if the format is not supported or is FormatAuto
//
// Note: FormatAuto is explicitly not supported as it requires format detection first.
//
// Example:
//
//	err := ValidateFormat(FormatPEM, []KeyFormat{FormatPEM, FormatDER})
//	if err != nil {
//		log.Printf("Format not supported: %v", err)
//	}
func ValidateFormat(format KeyFormat, supportedFormats []KeyFormat) error {
	if format == FormatAuto {
		return NewFormatError(FormatAuto, "auto-detection not supported for this operation", nil)
	}

	for _, supported := range supportedFormats {
		if format == supported {
			return nil
		}
	}

	return NewFormatError(format, "format not supported for this operation", nil)
}

