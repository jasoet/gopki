// File raw.go implements a custom binary format for encrypted data that provides
// compact representation with minimal overhead while maintaining all necessary metadata.
//
// The Raw format is designed for high-performance applications where minimal overhead
// and fast encoding/decoding are priorities. It uses a well-defined binary structure
// with magic bytes for format identification and version control for future evolution.
//
// Format structure (binary layout):
//
//	+===============================================+
//	| Magic Bytes (4)     | "GOPK"                |
//	| Version (1)         | 0x01                  |
//	| Algorithm ID (1)    | 0x01-0x05             |
//	| Timestamp (8)       | Unix timestamp        |
//	| Data Length (4)     | Length of payload     |
//	| Encrypted Data (N)  | Actual encrypted data |
//	| IV Length (2)       | Length of IV          |
//	| IV Data (N)         | Initialization Vector |
//	| Tag Length (2)      | Length of auth tag    |
//	| Tag Data (N)        | Authentication tag    |
//	| Key Length (2)      | Length of encrypted key|
//	| Encrypted Key (N)   | Encrypted symmetric key|
//	| Metadata Length (4) | Length of JSON metadata|
//	| Metadata (N)        | JSON-encoded metadata |
//	+===============================================+
//
// Format characteristics:
//   - Compact binary representation
//   - Big-endian byte ordering for cross-platform compatibility
//   - Magic bytes "GOPK" for format identification
//   - Version byte for future format evolution
//   - Variable-length fields with explicit length prefixes
//   - JSON metadata for extensibility
//   - Self-contained (includes all necessary decryption metadata)
//
// Performance characteristics:
//   - Minimal encoding/decoding overhead
//   - Efficient binary operations
//   - No external dependencies for parsing
//   - Suitable for high-throughput applications
//   - Memory-efficient streaming support
//
// Use cases:
//   - High-performance applications
//   - Custom protocols
//   - Embedded systems
//   - Internal storage formats
//   - Network protocols with bandwidth constraints
//
// Security considerations:
//   - Format structure is not encrypted (metadata is visible)
//   - Algorithm identification is in plaintext
//   - Timestamp information is in plaintext
//   - Consider these factors when choosing this format for sensitive applications
package formats

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jasoet/gopki/encryption"
)

// RawFormat implements the Format interface for the custom binary format.
//
// This format handler provides efficient encoding and decoding of encrypted data
// using a compact binary representation. It's optimized for performance and
// minimal overhead while maintaining all necessary metadata for decryption.
//
// The format is stateless and thread-safe, making it suitable for concurrent
// operations. All encoding and decoding operations are performed in memory
// with no external dependencies.
//
// Algorithm mapping:
//   - 0x01: RSA-OAEP
//   - 0x02: ECDH
//   - 0x03: X25519
//   - 0x04: AES-GCM
//   - 0x05: Envelope
//   - 0x00: Unknown/unsupported
type RawFormat struct{}

// NewRawFormat creates a new raw format handler instance.
//
// Returns:
//   - *RawFormat: A new format handler ready for encoding/decoding operations
//
// Example:
//
//	format := NewRawFormat()
//	encoded, err := format.Encode(encryptedData)
//	if err != nil {
//		log.Fatal("Encoding failed:", err)
//	}
func NewRawFormat() *RawFormat {
	return &RawFormat{}
}

// Name returns the format name
func (f *RawFormat) Name() string {
	return string(encryption.FormatRaw)
}

// Encode converts EncryptedData to the custom raw binary format.
//
// This method serializes all components of the encrypted data structure into
// a compact binary representation using big-endian byte ordering for cross-platform
// compatibility. The format includes magic bytes for identification and a version
// byte for future evolution.
//
// Binary format structure:
//   - Magic bytes (4): "GOPK" - Format identification
//   - Version (1): 0x01 - Format version for compatibility
//   - Algorithm (1): Algorithm identifier (0x01-0x05)
//   - Timestamp (8): Unix timestamp (big-endian int64)
//   - Data length (4): Length of encrypted data (big-endian uint32)
//   - Data (N): Encrypted data bytes
//   - IV length (2): Length of IV (big-endian uint16, 0 if no IV)
//   - IV (N): Initialization vector bytes
//   - Tag length (2): Length of authentication tag (big-endian uint16, 0 if no tag)
//   - Tag (N): Authentication tag bytes
//   - Encrypted key length (2): Length of encrypted key (big-endian uint16, 0 if none)
//   - Encrypted key (N): Encrypted symmetric key bytes
//   - Metadata length (4): Length of JSON metadata (big-endian uint32, 0 if none)
//   - Metadata (N): JSON-encoded metadata
//
// Parameters:
//   - data: The encrypted data structure to encode (must not be nil)
//
// Returns:
//   - []byte: Binary-encoded data ready for storage or transmission
//   - error: Encoding errors including JSON marshaling failures
//
// Error conditions:
//   - Nil input data
//   - JSON marshaling failure for metadata
//   - Binary write operations failure
//
// Example:
//
//	format := NewRawFormat()
//	encryptedData := &encryption.EncryptedData{
//		Algorithm: encryption.AlgorithmRSAOAEP,
//		Data:      []byte("encrypted content"),
//		Timestamp: time.Now(),
//	}
//
//	encoded, err := format.Encode(encryptedData)
//	if err != nil {
//		log.Fatal("Failed to encode:", err)
//	}
//	fmt.Printf("Encoded %d bytes\n", len(encoded))
func (f *RawFormat) Encode(data *encryption.EncryptedData) ([]byte, error) {
	var buf bytes.Buffer

	// Write magic bytes
	if _, err := buf.Write([]byte("GOPK")); err != nil {
		return nil, err
	}

	// Write version
	if err := buf.WriteByte(0x01); err != nil {
		return nil, err
	}

	// Write algorithm identifier
	algID := algorithmToByte(data.Algorithm)
	if err := buf.WriteByte(algID); err != nil {
		return nil, err
	}

	// Write timestamp
	timestamp := data.Timestamp.Unix()
	if err := binary.Write(&buf, binary.BigEndian, timestamp); err != nil {
		return nil, err
	}

	// Write encrypted data
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(data.Data))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(data.Data); err != nil {
		return nil, err
	}

	// Write IV
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(data.IV))); err != nil {
		return nil, err
	}
	if len(data.IV) > 0 {
		if _, err := buf.Write(data.IV); err != nil {
			return nil, err
		}
	}

	// Write tag
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(data.Tag))); err != nil {
		return nil, err
	}
	if len(data.Tag) > 0 {
		if _, err := buf.Write(data.Tag); err != nil {
			return nil, err
		}
	}

	// Write encrypted key
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(data.EncryptedKey))); err != nil {
		return nil, err
	}
	if len(data.EncryptedKey) > 0 {
		if _, err := buf.Write(data.EncryptedKey); err != nil {
			return nil, err
		}
	}

	// Write metadata
	var metadataBytes []byte
	if data.Metadata != nil && len(data.Metadata) > 0 {
		var err error
		metadataBytes, err = json.Marshal(data.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	if err := binary.Write(&buf, binary.BigEndian, uint32(len(metadataBytes))); err != nil {
		return nil, err
	}
	if len(metadataBytes) > 0 {
		if _, err := buf.Write(metadataBytes); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Decode parses raw binary format into EncryptedData
func (f *RawFormat) Decode(data []byte) (*encryption.EncryptedData, error) {
	if len(data) < 14 {
		return nil, errors.New("data too short for raw format")
	}

	buf := bytes.NewReader(data)

	// Read and verify magic bytes
	magic := make([]byte, 4)
	if _, err := buf.Read(magic); err != nil {
		return nil, err
	}
	if string(magic) != "GOPK" {
		return nil, errors.New("invalid magic bytes")
	}

	// Read version
	version, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != 0x01 {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read algorithm
	algID, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	algorithm := byteToAlgorithm(algID)

	// Read timestamp
	var timestamp int64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}

	result := &encryption.EncryptedData{
		Algorithm: algorithm,
		Format:    encryption.FormatRaw,
		Timestamp: time.Unix(timestamp, 0),
		Metadata:  make(map[string]interface{}),
	}

	// Read encrypted data
	var dataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return nil, err
	}
	if dataLen > 0 {
		result.Data = make([]byte, dataLen)
		if _, err := buf.Read(result.Data); err != nil {
			return nil, err
		}
	}

	// Read IV
	var ivLen uint16
	if err := binary.Read(buf, binary.BigEndian, &ivLen); err != nil {
		return nil, err
	}
	if ivLen > 0 {
		result.IV = make([]byte, ivLen)
		if _, err := buf.Read(result.IV); err != nil {
			return nil, err
		}
	}

	// Read tag
	var tagLen uint16
	if err := binary.Read(buf, binary.BigEndian, &tagLen); err != nil {
		return nil, err
	}
	if tagLen > 0 {
		result.Tag = make([]byte, tagLen)
		if _, err := buf.Read(result.Tag); err != nil {
			return nil, err
		}
	}

	// Read encrypted key
	var keyLen uint16
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return nil, err
	}
	if keyLen > 0 {
		result.EncryptedKey = make([]byte, keyLen)
		if _, err := buf.Read(result.EncryptedKey); err != nil {
			return nil, err
		}
	}

	// Read metadata
	var metadataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &metadataLen); err != nil {
		return nil, err
	}
	if metadataLen > 0 {
		metadataBytes := make([]byte, metadataLen)
		if _, err := buf.Read(metadataBytes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(metadataBytes, &result.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return result, nil
}

// algorithmToByte converts an EncryptionAlgorithm to a byte identifier
func algorithmToByte(alg encryption.EncryptionAlgorithm) byte {
	switch alg {
	case encryption.AlgorithmRSAOAEP:
		return 0x01
	case encryption.AlgorithmECDH:
		return 0x02
	case encryption.AlgorithmX25519:
		return 0x03
	case encryption.AlgorithmAESGCM:
		return 0x04
	case encryption.AlgorithmEnvelope:
		return 0x05
	default:
		return 0x00
	}
}

// byteToAlgorithm converts a byte identifier to an EncryptionAlgorithm
func byteToAlgorithm(b byte) encryption.EncryptionAlgorithm {
	switch b {
	case 0x01:
		return encryption.AlgorithmRSAOAEP
	case 0x02:
		return encryption.AlgorithmECDH
	case 0x03:
		return encryption.AlgorithmX25519
	case 0x04:
		return encryption.AlgorithmAESGCM
	case 0x05:
		return encryption.AlgorithmEnvelope
	default:
		return ""
	}
}