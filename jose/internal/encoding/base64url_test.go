package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeBytes(t *testing.T) {
	input := []byte("hello world")
	encoded := EncodeBytes(input)
	assert.NotEmpty(t, encoded)
	// Base64URL should not have padding
	assert.NotContains(t, encoded, "=")
}

func TestDecodeString(t *testing.T) {
	original := []byte("test data")
	encoded := EncodeBytes(original)

	decoded, err := DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestDecodeStringError(t *testing.T) {
	_, err := DecodeString("!!!invalid base64!!!")
	assert.Error(t, err)
}

func TestEncodeJSON(t *testing.T) {
	data := map[string]string{"key": "value"}
	encoded, err := EncodeJSON(data)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
}

func TestDecodeJSON(t *testing.T) {
	data := map[string]string{"key": "value"}
	encoded, _ := EncodeJSON(data)

	var decoded map[string]string
	err := DecodeJSON(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestDecodeJSONErrorInvalidBase64(t *testing.T) {
	var result map[string]string
	err := DecodeJSON("!!!invalid!!!", &result)
	assert.Error(t, err)
}

func TestDecodeJSONErrorInvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON
	invalidJSON := EncodeBytes([]byte("{invalid json}"))
	var result map[string]string
	err := DecodeJSON(invalidJSON, &result)
	assert.Error(t, err)
}
