// Package formats provides encryption output format implementations for the GoPKI
// encryption package, supporting multiple standardized and custom formats.
//
// This package implements a pluggable format system that allows encrypted data
// to be encoded in different formats for various use cases and compatibility
// requirements. Each format provides different advantages and is suitable for
// different scenarios.
//
// Supported formats:
//   - Raw: Custom binary format with magic bytes for format identification
//   - PKCS#7: Standard ASN.1 DER-encoded format for broad compatibility
//   - CMS: Cryptographic Message Syntax format for enterprise environments
//
// Format characteristics:
//
// Raw Format:
//   - Compact binary representation
//   - Fast encoding/decoding
//   - Custom magic bytes for format detection
//   - Minimal overhead
//   - Suitable for: High-performance applications, embedded systems, custom protocols
//
// PKCS#7 Format:
//   - Standard ASN.1 DER encoding
//   - Broad compatibility with existing tools
//   - Well-defined structure
//   - Industry standard
//   - Suitable for: Interoperability, standard compliance, enterprise integration
//
// CMS Format:
//   - RFC 5652 Cryptographic Message Syntax
//   - Advanced features and extensibility
//   - Support for complex scenarios
//   - Future-proof design
//   - Suitable for: Advanced PKI scenarios, multi-recipient encryption, standards compliance
//
// Architecture:
//   The format system uses a registry pattern where formats implement the Format
//   interface and are registered at initialization. This allows for easy extension
//   with custom formats while maintaining type safety and consistent behavior.
//
// Usage examples:
//
//	// Basic format encoding
//	import "github.com/jasoet/gopki/encryption/formats"
//
//	// Encode encrypted data in PKCS#7 format
//	pkcs7Data, err := formats.Encode(encryptedData, encryption.FormatPKCS7)
//	if err != nil {
//		log.Fatal("Format encoding failed:", err)
//	}
//
//	// Decode from known format
//	decryptedData, err := formats.Decode(pkcs7Data, encryption.FormatPKCS7)
//	if err != nil {
//		log.Fatal("Format decoding failed:", err)
//	}
//
//	// Auto-detect format
//	detectedFormat, err := formats.AutoDetectFormat(someEncryptedData)
//	if err != nil {
//		log.Fatal("Format detection failed:", err)
//	}
//	fmt.Printf("Detected format: %s\n", detectedFormat)
//
// Custom format implementation:
//
//	// Implement the Format interface
//	type MyCustomFormat struct{}
//
//	func (f *MyCustomFormat) Encode(data *encryption.EncryptedData) ([]byte, error) {
//		// Custom encoding logic
//		return encodedData, nil
//	}
//
//	func (f *MyCustomFormat) Decode(data []byte) (*encryption.EncryptedData, error) {
//		// Custom decoding logic
//		return decryptedData, nil
//	}
//
//	func (f *MyCustomFormat) Name() string {
//		return "MyCustomFormat"
//	}
//
//	// Register the custom format
//	formats.Register("custom", &MyCustomFormat{})
package formats

import (
	"errors"
	"fmt"

	"github.com/jasoet/gopki/encryption"
)

// Format defines the interface that all encryption format handlers must implement.
//
// This interface provides a consistent API for encoding and decoding encrypted data
// across different formats. Implementations must handle the conversion between
// the internal EncryptedData representation and their specific format encoding.
//
// Interface requirements:
//   - Encode must produce format-compliant output that can be decoded
//   - Decode must handle all valid format variations and error gracefully
//   - Name must return a unique, human-readable format identifier
//   - Implementations should be stateless and thread-safe
//
// Example implementation:
//
//	type MyFormat struct{}
//
//	func (f *MyFormat) Encode(data *encryption.EncryptedData) ([]byte, error) {
//		// Convert EncryptedData to format-specific representation
//		return formatSpecificBytes, nil
//	}
//
//	func (f *MyFormat) Decode(data []byte) (*encryption.EncryptedData, error) {
//		// Parse format-specific data back to EncryptedData
//		return encryptedData, nil
//	}
//
//	func (f *MyFormat) Name() string {
//		return "MyFormat"
//	}
type Format interface {
	// Encode converts encrypted data to the specific format representation.
	//
	// This method takes the internal EncryptedData structure and converts it
	// to the format's specific encoding (binary, ASN.1, etc.). The output
	// should be suitable for storage, transmission, or interoperability.
	//
	// Parameters:
	//   - data: The encrypted data to encode (must not be nil)
	//
	// Returns:
	//   - []byte: Format-specific encoded data
	//   - error: Encoding errors or validation failures
	Encode(data *encryption.EncryptedData) ([]byte, error)

	// Decode parses format-specific data back into the internal EncryptedData structure.
	//
	// This method takes format-specific encoded data and converts it back to
	// the internal representation for use with the encryption system. It should
	// validate the format and handle any format-specific parsing requirements.
	//
	// Parameters:
	//   - data: Format-specific encoded data (must not be empty)
	//
	// Returns:
	//   - *encryption.EncryptedData: Parsed encrypted data structure
	//   - error: Parsing errors, format validation failures, or corruption detection
	Decode(data []byte) (*encryption.EncryptedData, error)

	// Name returns the human-readable name of the format.
	//
	// This should be a unique identifier for the format that can be used
	// for logging, debugging, and user interfaces. It should match the
	// format constant used for registration.
	//
	// Returns:
	//   - string: Format name (e.g., "Raw", "PKCS#7", "CMS")
	Name() string
}

// Registry manages available encryption formats using a thread-safe registry pattern.
//
// The registry maintains a mapping of format identifiers to their corresponding
// Format implementations. It provides centralized management of all supported
// formats and ensures consistent access across the application.
//
// Thread safety:
//   - Read operations (Get, ListFormats) are thread-safe after initialization
//   - Write operations (Register) should only be performed during initialization
//   - The global registry is initialized once at package load time
//
// Design principles:
//   - Singleton pattern for global format access
//   - Simple registration mechanism for extensibility
//   - Clear separation between format logic and registry management
type Registry struct {
	formats map[encryption.EncryptionFormat]Format
}

// globalRegistry is the singleton format registry instance.
//
// This global registry is initialized at package load time and contains
// all registered format handlers. It provides the backing store for all
// package-level format operations.
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

// AutoDetectFormat attempts to automatically detect the format of encrypted data
// by trying to decode it with each registered format.
//
// This function is useful when you have encrypted data of unknown format and need
// to determine how to decode it. It tries each format in order of likelihood:
// Raw (most common), PKCS#7 (standard), CMS (advanced).
//
// Detection algorithm:
//   1. Try Raw format (fastest, most common)
//   2. Try PKCS#7 format (standard ASN.1)
//   3. Try CMS format (most complex)
//   4. Return error if no format succeeds
//
// Parameters:
//   - data: The encrypted data to analyze (must not be empty)
//
// Returns:
//   - encryption.EncryptionFormat: The detected format identifier
//   - error: Detection failure if no format can parse the data
//
// Performance considerations:
//   - Detection requires attempting to parse with each format
//   - Ordering optimized for common cases (Raw first)
//   - Consider caching results for repeated detection of same data
//
// Example:
//
//	unknownData := []byte{...}  // Encrypted data from unknown source
//	format, err := formats.AutoDetectFormat(unknownData)
//	if err != nil {
//		log.Fatal("Could not detect format:", err)
//	}
//	fmt.Printf("Detected format: %s\n", format)
//
//	// Now decode with the detected format
//	encryptedData, err := formats.Decode(unknownData, format)
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