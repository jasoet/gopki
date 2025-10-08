// Package encoding provides Base64URL encoding utilities for JOSE implementations.
// This is an internal package shared by JWT and JWS modules.
package encoding

import (
	"encoding/base64"
	"encoding/json"
)

// Base64URLEncoding is the Base64URL encoding without padding as per RFC 7515
var Base64URLEncoding = base64.RawURLEncoding

// EncodeBytes encodes data using Base64URL (no padding)
func EncodeBytes(data []byte) string {
	return Base64URLEncoding.EncodeToString(data)
}

// DecodeString decodes Base64URL encoded data
func DecodeString(s string) ([]byte, error) {
	return Base64URLEncoding.DecodeString(s)
}

// EncodeJSON JSON marshals and Base64URL encodes a value
func EncodeJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return EncodeBytes(data), nil
}

// DecodeJSON Base64URL decodes and JSON unmarshals into a value
func DecodeJSON(s string, v interface{}) error {
	data, err := DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
