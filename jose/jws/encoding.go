package jws

import "github.com/jasoet/gopki/jose/internal/encoding"

// base64URLEncode encodes data using Base64URL (no padding)
func base64URLEncode(data []byte) string {
	return encoding.EncodeBytes(data)
}

// base64URLDecode decodes Base64URL encoded data
func base64URLDecode(s string) ([]byte, error) {
	return encoding.DecodeString(s)
}
