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

// RawFormat handles the raw binary format for encrypted data
type RawFormat struct{}

// NewRawFormat creates a new raw format handler
func NewRawFormat() *RawFormat {
	return &RawFormat{}
}

// Name returns the format name
func (f *RawFormat) Name() string {
	return string(encryption.FormatRaw)
}

// Encode converts EncryptedData to raw binary format
// Format structure:
// - Magic bytes (4): "GOPK"
// - Version (1): 0x01
// - Algorithm (1): algorithm identifier
// - Timestamp (8): Unix timestamp
// - Data length (4): length of encrypted data
// - Data: encrypted data bytes
// - IV length (2): length of IV (0 if no IV)
// - IV: initialization vector bytes
// - Tag length (2): length of tag (0 if no tag)
// - Tag: authentication tag bytes
// - Encrypted key length (2): length of encrypted key (0 if none)
// - Encrypted key: encrypted symmetric key
// - Metadata length (4): length of JSON metadata (0 if none)
// - Metadata: JSON-encoded metadata
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