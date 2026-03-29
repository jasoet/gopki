// Package format defines types for cryptographic key encoding formats.
package format

type (
	// PEM represents a PEM-encoded key or certificate.
	PEM []byte
	// DER represents a DER-encoded key or certificate.
	DER []byte
	// SSH represents an SSH-formatted public key string.
	SSH string
)
