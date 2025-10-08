package jwt

import "github.com/jasoet/gopki/jose/internal/encoding"

// base64URLEncode encodes data using Base64URL (no padding)
func base64URLEncode(data []byte) string {
	return encoding.EncodeBytes(data)
}

// base64URLDecode decodes Base64URL encoded data
func base64URLDecode(s string) ([]byte, error) {
	return encoding.DecodeString(s)
}

// encodeSegment JSON marshals and Base64URL encodes a value
func encodeSegment(v interface{}) (string, error) {
	return encoding.EncodeJSON(v)
}

// decodeSegment Base64URL decodes and JSON unmarshals into a value
func decodeSegment(s string, v interface{}) error {
	return encoding.DecodeJSON(s, v)
}
