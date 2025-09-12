package format

import (
	"fmt"
	"strings"
)

type KeyFormat int

const (
	FormatPEM KeyFormat = iota
	FormatDER
	FormatSSH
	FormatAuto
)

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

type EncodedKey struct {
	Data    []byte    // The encoded key data
	Format  KeyFormat // The format of the encoded data
	Comment string    // Optional comment (used for SSH keys)
	KeyType string    // Key algorithm type (RSA, ECDSA, Ed25519)
}

type EncodedKeyPair struct {
	Private *EncodedKey
	Public  *EncodedKey
}

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

func NewFormatError(format KeyFormat, message string, cause error) *FormatError {
	return &FormatError{
		Format:  format,
		Message: message,
		Cause:   cause,
	}
}

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
