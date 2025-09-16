package formats

import (
	"errors"
	"fmt"

	"github.com/jasoet/gopki/encryption"
)

// Format defines the interface for encryption format handlers
type Format interface {
	// Encode converts encrypted data to the specific format
	Encode(data *encryption.EncryptedData) ([]byte, error)
	// Decode parses format-specific data into EncryptedData
	Decode(data []byte) (*encryption.EncryptedData, error)
	// Name returns the format name
	Name() string
}

// Registry manages available encryption formats
type Registry struct {
	formats map[encryption.EncryptionFormat]Format
}

// globalRegistry is the singleton format registry
var globalRegistry = &Registry{
	formats: make(map[encryption.EncryptionFormat]Format),
}

// Register adds a new format to the registry
func Register(format encryption.EncryptionFormat, handler Format) {
	globalRegistry.formats[format] = handler
}

// Get retrieves a format handler by name
func Get(format encryption.EncryptionFormat) (Format, error) {
	handler, exists := globalRegistry.formats[format]
	if !exists {
		return nil, fmt.Errorf("format %s not registered", format)
	}
	return handler, nil
}

// ListFormats returns all registered format names
func ListFormats() []encryption.EncryptionFormat {
	var formats []encryption.EncryptionFormat
	for format := range globalRegistry.formats {
		formats = append(formats, format)
	}
	return formats
}

// Encode encodes encrypted data using the specified format
func Encode(data *encryption.EncryptedData, format encryption.EncryptionFormat) ([]byte, error) {
	if data == nil {
		return nil, errors.New("encrypted data is nil")
	}

	handler, err := Get(format)
	if err != nil {
		return nil, err
	}

	return handler.Encode(data)
}

// Decode decodes data from the specified format
func Decode(data []byte, format encryption.EncryptionFormat) (*encryption.EncryptedData, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	handler, err := Get(format)
	if err != nil {
		return nil, err
	}

	return handler.Decode(data)
}

// AutoDetectFormat attempts to detect the format of encrypted data
func AutoDetectFormat(data []byte) (encryption.EncryptionFormat, error) {
	if len(data) == 0 {
		return "", errors.New("data is empty")
	}

	// Try each format in order of likelihood
	formats := []encryption.EncryptionFormat{
		encryption.FormatRaw,
		encryption.FormatPKCS7,
		encryption.FormatCMS,
	}

	for _, format := range formats {
		handler, err := Get(format)
		if err != nil {
			continue
		}

		// Try to decode with this format
		if _, err := handler.Decode(data); err == nil {
			return format, nil
		}
	}

	return "", errors.New("unable to detect format")
}

// ValidateFormat checks if a format is supported
func ValidateFormat(format encryption.EncryptionFormat) error {
	if _, err := Get(format); err != nil {
		return fmt.Errorf("unsupported format: %s", format)
	}
	return nil
}

// init registers the default formats
func init() {
	// Register the built-in formats
	Register(encryption.FormatRaw, NewRawFormat())
	Register(encryption.FormatPKCS7, NewPKCS7Format())
	Register(encryption.FormatCMS, NewCMSFormat())
}