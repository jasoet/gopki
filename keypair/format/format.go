package format

import (
	"fmt"
	"strings"
)

// KeyFormat represents the encoding format for cryptographic keys
type KeyFormat int

const (
	// FormatPEM represents PEM (Privacy-Enhanced Mail) format - base64 encoded with headers
	FormatPEM KeyFormat = iota
	// FormatDER represents DER (Distinguished Encoding Rules) format - binary encoded
	FormatDER
	// FormatSSH represents SSH key format - used for SSH authentication
	FormatSSH
	// FormatAuto automatically detects the format from input data
	FormatAuto
)

// String returns the string representation of the format
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

// EncodedKey represents a cryptographic key in a specific encoding format
type EncodedKey struct {
	Data    []byte    // The encoded key data
	Format  KeyFormat // The format of the encoded data
	Comment string    // Optional comment (used for SSH keys)
	KeyType string    // Key algorithm type (RSA, ECDSA, Ed25519)
}

// EncodedKeyPair represents a pair of encoded keys (private and public)
type EncodedKeyPair struct {
	Private *EncodedKey
	Public  *EncodedKey
}

// FormatError represents an error specific to key format operations
type FormatError struct {
	Format  KeyFormat
	Message string
	Cause   error
}

func (e *FormatError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s format error: %s: %v", e.Format, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s format error: %s", e.Format, e.Message)
}

func (e *FormatError) Unwrap() error {
	return e.Cause
}

// NewFormatError creates a new format-specific error
func NewFormatError(format KeyFormat, message string, cause error) *FormatError {
	return &FormatError{
		Format:  format,
		Message: message,
		Cause:   cause,
	}
}

// DetectFormat attempts to automatically detect the format of key data
func DetectFormat(data []byte) (KeyFormat, error) {
	if len(data) == 0 {
		return FormatAuto, NewFormatError(FormatAuto, "empty data", nil)
	}

	dataStr := string(data)

	// Check for SSH private key format first (before PEM check)
	if strings.Contains(dataStr, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return FormatSSH, nil
	}

	// Check for PEM format - starts with "-----BEGIN" (but not SSH private key)
	if strings.HasPrefix(dataStr, "-----BEGIN") {
		return FormatPEM, nil
	}

	// Check for SSH format - contains algorithm identifier
	if strings.HasPrefix(dataStr, "ssh-rsa ") ||
		strings.HasPrefix(dataStr, "ssh-ed25519 ") ||
		strings.HasPrefix(dataStr, "ecdsa-sha2-") {
		return FormatSSH, nil
	}

	// If it's not text-based and has reasonable length, assume DER
	// DER is binary format, so we check if it's not printable text
	if !isPrintableText(data) && len(data) > 50 {
		return FormatDER, nil
	}

	return FormatAuto, NewFormatError(FormatAuto, "unable to detect format", nil)
}

// isPrintableText checks if data consists mostly of printable characters
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

	// Consider it text if more than 95% of bytes are printable
	return float64(printableCount)/float64(len(data)) > 0.95
}

// ValidateFormat checks if the given format is supported for the operation
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
