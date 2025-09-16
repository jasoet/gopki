package formats

import (
	"testing"
	"time"

	"github.com/jasoet/gopki/encryption"
)

func TestFormatRegistry(t *testing.T) {
	t.Run("ListFormats", func(t *testing.T) {
		formats := ListFormats()
		expectedFormats := []encryption.EncryptionFormat{
			encryption.FormatRaw,
			encryption.FormatPKCS7,
			encryption.FormatCMS,
		}

		// Check that all expected formats are registered
		for _, expected := range expectedFormats {
			found := false
			for _, format := range formats {
				if format == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected format %s not found in registry", expected)
			}
		}
	})

	t.Run("Get Format Handler", func(t *testing.T) {
		// Test getting each format
		formats := []encryption.EncryptionFormat{
			encryption.FormatRaw,
			encryption.FormatPKCS7,
			encryption.FormatCMS,
		}

		for _, format := range formats {
			handler, err := Get(format)
			if err != nil {
				t.Errorf("Failed to get handler for format %s: %v", format, err)
				continue
			}

			if handler == nil {
				t.Errorf("Handler for format %s is nil", format)
			}

			// Check that the handler name matches
			if handler.Name() != string(format) {
				t.Errorf("Handler name mismatch: expected %s, got %s", format, handler.Name())
			}
		}
	})

	t.Run("Get Unknown Format", func(t *testing.T) {
		_, err := Get("unknown")
		if err == nil {
			t.Error("Expected error for unknown format")
		}
	})

	t.Run("ValidateFormat", func(t *testing.T) {
		// Valid formats
		validFormats := []encryption.EncryptionFormat{
			encryption.FormatRaw,
			encryption.FormatPKCS7,
			encryption.FormatCMS,
		}

		for _, format := range validFormats {
			if err := ValidateFormat(format); err != nil {
				t.Errorf("Valid format %s failed validation: %v", format, err)
			}
		}

		// Invalid format
		if err := ValidateFormat("invalid"); err == nil {
			t.Error("Expected error for invalid format")
		}
	})
}

func TestRawFormat(t *testing.T) {
	format := NewRawFormat()

	testData := &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmAESGCM,
		Format:       encryption.FormatRaw,
		Data:         []byte("encrypted data"),
		IV:           []byte("initialization"),
		Tag:          []byte("auth tag"),
		EncryptedKey: []byte("encrypted key"),
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
	}

	t.Run("Encode and Decode", func(t *testing.T) {
		// Encode
		encoded, err := format.Encode(testData)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		if len(encoded) == 0 {
			t.Error("Encoded data is empty")
		}

		// Decode
		decoded, err := format.Decode(encoded)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		// Verify fields
		if decoded.Algorithm != testData.Algorithm {
			t.Errorf("Algorithm mismatch: expected %s, got %s", testData.Algorithm, decoded.Algorithm)
		}

		if string(decoded.Data) != string(testData.Data) {
			t.Error("Data mismatch")
		}

		if string(decoded.IV) != string(testData.IV) {
			t.Error("IV mismatch")
		}

		if string(decoded.Tag) != string(testData.Tag) {
			t.Error("Tag mismatch")
		}

		if string(decoded.EncryptedKey) != string(testData.EncryptedKey) {
			t.Error("EncryptedKey mismatch")
		}

		// Check metadata
		if v, ok := decoded.Metadata["key1"].(string); !ok || v != "value1" {
			t.Error("Metadata key1 mismatch")
		}

		// JSON unmarshaling converts numbers to float64
		if v, ok := decoded.Metadata["key2"].(float64); !ok || v != 42 {
			t.Error("Metadata key2 mismatch")
		}
	})

	t.Run("Invalid Data", func(t *testing.T) {
		// Too short data
		_, err := format.Decode([]byte("short"))
		if err == nil {
			t.Error("Expected error for short data")
		}

		// Invalid magic bytes
		invalidData := []byte("BADMAGIC12345678901234567890")
		_, err = format.Decode(invalidData)
		if err == nil {
			t.Error("Expected error for invalid magic bytes")
		}
	})

	t.Run("Empty Fields", func(t *testing.T) {
		emptyData := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmAESGCM,
			Format:    encryption.FormatRaw,
			Timestamp: time.Now(),
			Metadata:  make(map[string]interface{}),
		}

		encoded, err := format.Encode(emptyData)
		if err != nil {
			t.Fatalf("Failed to encode empty data: %v", err)
		}

		decoded, err := format.Decode(encoded)
		if err != nil {
			t.Fatalf("Failed to decode empty data: %v", err)
		}

		if decoded.Algorithm != emptyData.Algorithm {
			t.Error("Algorithm mismatch for empty data")
		}

		if len(decoded.Data) != 0 {
			t.Error("Expected empty data")
		}
	})
}

func TestPKCS7Format(t *testing.T) {
	format := NewPKCS7Format()

	testData := &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmRSAOAEP,
		Format:       encryption.FormatPKCS7,
		Data:         []byte("encrypted data"),
		EncryptedKey: []byte("encrypted key"),
		Recipients: []*encryption.RecipientInfo{
			{
				KeyID:                  []byte("key1"),
				EncryptedKey:           []byte("encrypted key 1"),
				KeyEncryptionAlgorithm: encryption.AlgorithmRSAOAEP,
			},
		},
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	t.Run("Encode and Decode", func(t *testing.T) {
		// Encode
		encoded, err := format.Encode(testData)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		if len(encoded) == 0 {
			t.Error("Encoded data is empty")
		}

		// Decode
		decoded, err := format.Decode(encoded)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		// PKCS7 may not preserve all fields exactly
		if string(decoded.Data) != string(testData.Data) {
			t.Error("Data mismatch")
		}

		// Check that we have recipients
		if len(decoded.Recipients) == 0 {
			t.Error("No recipients in decoded data")
		}
	})

	t.Run("Invalid PKCS7 Data", func(t *testing.T) {
		// Invalid ASN.1 data
		_, err := format.Decode([]byte("not asn.1 data"))
		if err == nil {
			t.Error("Expected error for invalid ASN.1 data")
		}
	})

	t.Run("Multiple Recipients", func(t *testing.T) {
		multiRecipientData := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmEnvelope,
			Format:    encryption.FormatPKCS7,
			Data:      []byte("encrypted data"),
			Recipients: []*encryption.RecipientInfo{
				{
					EncryptedKey:           []byte("key1"),
					KeyEncryptionAlgorithm: encryption.AlgorithmRSAOAEP,
				},
				{
					EncryptedKey:           []byte("key2"),
					KeyEncryptionAlgorithm: encryption.AlgorithmRSAOAEP,
				},
			},
		}

		encoded, err := format.Encode(multiRecipientData)
		if err != nil {
			t.Fatalf("Failed to encode multi-recipient data: %v", err)
		}

		decoded, err := format.Decode(encoded)
		if err != nil {
			t.Fatalf("Failed to decode multi-recipient data: %v", err)
		}

		if len(decoded.Recipients) < 2 {
			t.Errorf("Expected at least 2 recipients, got %d", len(decoded.Recipients))
		}
	})
}

func TestCMSFormat(t *testing.T) {
	format := NewCMSFormat()

	testData := &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmAESGCM,
		Format:       encryption.FormatCMS,
		Data:         []byte("encrypted data"),
		EncryptedKey: []byte("encrypted key"),
		Recipients: []*encryption.RecipientInfo{
			{
				KeyID:                  []byte("subject key id"),
				EncryptedKey:           []byte("encrypted key 1"),
				KeyEncryptionAlgorithm: encryption.AlgorithmRSAOAEP,
			},
		},
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	t.Run("Encode and Decode", func(t *testing.T) {
		// Encode
		encoded, err := format.Encode(testData)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		if len(encoded) == 0 {
			t.Error("Encoded data is empty")
		}

		// Decode
		decoded, err := format.Decode(encoded)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		// CMS should preserve the data
		if string(decoded.Data) != string(testData.Data) {
			t.Error("Data mismatch")
		}

		// Check recipients
		if len(decoded.Recipients) == 0 {
			t.Error("No recipients in decoded data")
		}
	})

	t.Run("Invalid CMS Data", func(t *testing.T) {
		// Invalid ASN.1 data
		_, err := format.Decode([]byte("not asn.1 data"))
		if err == nil {
			t.Error("Expected error for invalid ASN.1 data")
		}
	})

	t.Run("ValidateCMS", func(t *testing.T) {
		// Create valid CMS data
		validData := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmEnvelope,
			Format:    encryption.FormatCMS,
			Data:      []byte("test"),
		}

		encoded, err := format.Encode(validData)
		if err != nil {
			t.Fatalf("Failed to encode for validation: %v", err)
		}

		// Validate
		if err := ValidateCMS(encoded); err != nil {
			t.Errorf("Valid CMS data failed validation: %v", err)
		}

		// Invalid data
		if err := ValidateCMS([]byte("invalid")); err == nil {
			t.Error("Expected error for invalid CMS data")
		}
	})
}

func TestFormatConversion(t *testing.T) {
	// Test converting between formats
	originalData := &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmEnvelope,
		Format:       encryption.FormatRaw,
		Data:         []byte("test encrypted data"),
		IV:           []byte("test iv"),
		Tag:          []byte("test tag"),
		EncryptedKey: []byte("test key"),
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"test": "value",
		},
	}

	t.Run("Raw to PKCS7", func(t *testing.T) {
		// Encode as Raw
		rawFormat := NewRawFormat()
		rawEncoded, err := rawFormat.Encode(originalData)
		if err != nil {
			t.Fatalf("Failed to encode as raw: %v", err)
		}

		// Decode from Raw
		rawDecoded, err := rawFormat.Decode(rawEncoded)
		if err != nil {
			t.Fatalf("Failed to decode raw: %v", err)
		}

		// Change format and encode as PKCS7
		rawDecoded.Format = encryption.FormatPKCS7
		pkcs7Format := NewPKCS7Format()
		pkcs7Encoded, err := pkcs7Format.Encode(rawDecoded)
		if err != nil {
			t.Fatalf("Failed to encode as PKCS7: %v", err)
		}

		// Decode from PKCS7
		pkcs7Decoded, err := pkcs7Format.Decode(pkcs7Encoded)
		if err != nil {
			t.Fatalf("Failed to decode PKCS7: %v", err)
		}

		// Verify core data is preserved
		if string(pkcs7Decoded.Data) != string(originalData.Data) {
			t.Error("Data not preserved in format conversion")
		}
	})

	t.Run("Raw to CMS", func(t *testing.T) {
		// Encode as Raw
		rawFormat := NewRawFormat()
		rawEncoded, err := rawFormat.Encode(originalData)
		if err != nil {
			t.Fatalf("Failed to encode as raw: %v", err)
		}

		// Decode from Raw
		rawDecoded, err := rawFormat.Decode(rawEncoded)
		if err != nil {
			t.Fatalf("Failed to decode raw: %v", err)
		}

		// Change format and encode as CMS
		rawDecoded.Format = encryption.FormatCMS
		cmsFormat := NewCMSFormat()
		cmsEncoded, err := cmsFormat.Encode(rawDecoded)
		if err != nil {
			t.Fatalf("Failed to encode as CMS: %v", err)
		}

		// Decode from CMS
		cmsDecoded, err := cmsFormat.Decode(cmsEncoded)
		if err != nil {
			t.Fatalf("Failed to decode CMS: %v", err)
		}

		// Verify core data is preserved
		if string(cmsDecoded.Data) != string(originalData.Data) {
			t.Error("Data not preserved in format conversion")
		}
	})
}

func TestAutoDetectFormat(t *testing.T) {
	t.Run("Detect Raw Format", func(t *testing.T) {
		rawFormat := NewRawFormat()
		testData := &encryption.EncryptedData{
			Algorithm: encryption.AlgorithmAESGCM,
			Format:    encryption.FormatRaw,
			Data:      []byte("test"),
			Timestamp: time.Now(),
			Metadata:  make(map[string]interface{}),
		}

		encoded, err := rawFormat.Encode(testData)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		detectedFormat, err := AutoDetectFormat(encoded)
		if err != nil {
			t.Fatalf("Failed to auto-detect format: %v", err)
		}

		if detectedFormat != encryption.FormatRaw {
			t.Errorf("Expected raw format, got %s", detectedFormat)
		}
	})

	t.Run("Detect Unknown Format", func(t *testing.T) {
		_, err := AutoDetectFormat([]byte("random data that is not a valid format"))
		if err == nil {
			t.Error("Expected error for unknown format")
		}
	})

	t.Run("Empty Data", func(t *testing.T) {
		_, err := AutoDetectFormat([]byte{})
		if err == nil {
			t.Error("Expected error for empty data")
		}
	})
}

func TestHighLevelFormatFunctions(t *testing.T) {
	testData := &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmAESGCM,
		Format:       encryption.FormatRaw,
		Data:         []byte("test data"),
		IV:           []byte("test iv"),
		Tag:          []byte("test tag"),
		EncryptedKey: []byte("test key"),
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"key": "value",
		},
	}

	t.Run("Encode Function", func(t *testing.T) {
		formats := []encryption.EncryptionFormat{
			encryption.FormatRaw,
			encryption.FormatPKCS7,
			encryption.FormatCMS,
		}

		for _, format := range formats {
			encoded, err := Encode(testData, format)
			if err != nil {
				t.Errorf("Failed to encode with format %s: %v", format, err)
				continue
			}

			if len(encoded) == 0 {
				t.Errorf("Empty encoded data for format %s", format)
			}
		}
	})

	t.Run("Decode Function", func(t *testing.T) {
		// First encode the data
		encoded, err := Encode(testData, encryption.FormatRaw)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		// Now decode it
		decoded, err := Decode(encoded, encryption.FormatRaw)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		if string(decoded.Data) != string(testData.Data) {
			t.Error("Decoded data mismatch")
		}
	})

	t.Run("Encode Nil Data", func(t *testing.T) {
		_, err := Encode(nil, encryption.FormatRaw)
		if err == nil {
			t.Error("Expected error for nil data")
		}
	})

	t.Run("Decode Empty Data", func(t *testing.T) {
		_, err := Decode([]byte{}, encryption.FormatRaw)
		if err == nil {
			t.Error("Expected error for empty data")
		}
	})
}