package format

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jasoet/gopki/keypair"
)

// PrivateKeyToDER converts a private key to DER (Distinguished Encoding Rules) format.
// DER is a binary format that is more compact than PEM and faster to parse.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//
// Returns:
//   - Binary DER-encoded private key data
//   - Error if marshaling fails
//
// The function uses PKCS#8 encoding for maximum compatibility across different systems.
// DER format is typically 30% smaller than equivalent PEM format.
//
// Example:
//
//	derData, err := PrivateKeyToDER(rsaPrivateKey)
//	if err != nil {
//		log.Printf("DER conversion failed: %v", err)
//	}
func PrivateKeyToDER[T keypair.PrivateKey](privateKey T) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, NewFormatError(FormatDER, "failed to marshal private key to DER", err)
	}
	return derBytes, nil
}

// PublicKeyToDER converts a public key to DER (Distinguished Encoding Rules) format.
// DER is a binary format that provides compact storage and fast parsing.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//
// Returns:
//   - Binary DER-encoded public key data
//   - Error if marshaling fails
//
// The function uses PKIX encoding which is the standard for public key encoding
// in X.509 certificates and other PKI applications.
//
// Example:
//
//	derData, err := PublicKeyToDER(rsaPublicKey)
//	if err != nil {
//		log.Printf("DER conversion failed: %v", err)
//	}
func PublicKeyToDER[T keypair.PublicKey](publicKey T) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, NewFormatError(FormatDER, "failed to marshal public key to DER", err)
	}
	return derBytes, nil
}

// ParsePrivateKeyFromDER parses a private key from DER-encoded binary data.
// The function expects PKCS#8 encoded private key data and performs type-safe conversion.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - derData: DER-encoded private key data
//
// Returns:
//   - The parsed private key of the specified type
//   - Error if parsing fails or type doesn't match expected type
//
// The function validates that the parsed key matches the expected type,
// providing compile-time type safety with runtime verification.
//
// Example:
//
//	rsaKey, err := ParsePrivateKeyFromDER[*rsa.PrivateKey](derData)
//	if err != nil {
//		log.Printf("DER parsing failed: %v", err)
//	}
func ParsePrivateKeyFromDER[T keypair.PrivateKey](derData keypair.DER) (T, error) {
	var zero T

	privateKey, err := x509.ParsePKCS8PrivateKey(derData)
	if err != nil {
		return zero, NewFormatError(FormatDER, "failed to parse private key from DER", err)
	}

	typedKey, ok := privateKey.(T)
	if !ok {
		return zero, NewFormatError(FormatDER, fmt.Sprintf("private key is not of expected type %T", zero), nil)
	}

	return typedKey, nil
}

// ParsePublicKeyFromDER parses a public key from DER-encoded binary data.
// The function expects PKIX encoded public key data and performs type-safe conversion.
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - derData: DER-encoded public key data
//
// Returns:
//   - The parsed public key of the specified type
//   - Error if parsing fails or type doesn't match expected type
//
// The function validates that the parsed key matches the expected type,
// providing compile-time type safety with runtime verification.
//
// Example:
//
//	rsaKey, err := ParsePublicKeyFromDER[*rsa.PublicKey](derData)
//	if err != nil {
//		log.Printf("DER parsing failed: %v", err)
//	}
func ParsePublicKeyFromDER[T keypair.PublicKey](derData keypair.DER) (T, error) {
	var zero T

	publicKey, err := x509.ParsePKIXPublicKey(derData)
	if err != nil {
		return zero, NewFormatError(FormatDER, "failed to parse public key from DER", err)
	}

	typedKey, ok := publicKey.(T)
	if !ok {
		return zero, NewFormatError(FormatDER, fmt.Sprintf("public key is not of expected type %T", zero), nil)
	}

	return typedKey, nil
}

// ConvertPEMToDER converts PEM-encoded key data to DER binary format.
// This function extracts the Base64-decoded data from PEM format, removing headers.
//
// Parameters:
//   - pemData: PEM-encoded key data with headers ("-----BEGIN...-----")
//
// Returns:
//   - Binary DER-encoded data
//   - Error if PEM decoding fails
//
// The conversion results in significantly smaller data size (typically 30% reduction)
// and faster parsing performance. PEM headers and Base64 encoding are removed.
//
// Example:
//
//	derData, err := ConvertPEMToDER(pemKeyData)
//	if err != nil {
//		log.Printf("PEM to DER conversion failed: %v", err)
//	}
func ConvertPEMToDER(pemData keypair.PEM) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, NewFormatError(FormatDER, "failed to decode PEM block", nil)
	}

	return block.Bytes, nil
}

// ConvertDERToPEM converts DER binary data to PEM format with appropriate headers.
// The function automatically detects whether the data is a private or public key.
//
// Parameters:
//   - derData: DER-encoded binary key data
//   - keyType: Optional key type hint (currently unused, detection is automatic)
//
// Returns:
//   - PEM-encoded data with appropriate headers
//   - Error if conversion fails
//
// The function automatically determines the correct PEM block type:
//   - "PRIVATE KEY" for PKCS#8 private keys
//   - "PUBLIC KEY" for PKIX public keys
//
// Example:
//
//	pemData, err := ConvertDERToPEM(derData, "")
//	if err != nil {
//		log.Printf("DER to PEM conversion failed: %v", err)
//	}
func ConvertDERToPEM(derData keypair.DER, keyType string) (keypair.PEM, error) {
	var blockType string

	if isPrivateKeyDER(derData) {
		blockType = "PRIVATE KEY"
	} else {
		blockType = "PUBLIC KEY"
	}

	pemBlock := &pem.Block{
		Type:  blockType,
		Bytes: derData,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if pemData == nil {
		return nil, NewFormatError(FormatPEM, "failed to encode DER to PEM", nil)
	}

	return pemData, nil
}

// isPrivateKeyDER determines if DER data contains a private key by attempting to parse it.
// This is an internal utility function used for automatic key type detection.
//
// Parameters:
//   - derData: DER-encoded binary data
//
// Returns:
//   - true if the data can be parsed as a PKCS#8 private key, false otherwise
//
// The function attempts to parse the data as a PKCS#8 private key without
// causing side effects. It's used to distinguish between private and public keys.
func isPrivateKeyDER(derData keypair.DER) bool {
	_, err := x509.ParsePKCS8PrivateKey(derData)
	return err == nil
}

// GetKeyTypeFromDER determines the cryptographic algorithm of a DER-encoded key.
// The function attempts to parse the key as both private and public key formats.
//
// Parameters:
//   - derData: DER-encoded binary key data
//
// Returns:
//   - String identifier of the key type ("RSA", "ECDSA", "Ed25519", or "Unknown")
//   - Error if the data cannot be parsed as either private or public key
//
// The function tries PKCS#8 private key parsing first, then PKIX public key parsing.
// This allows it to work with both private and public keys automatically.
//
// Example:
//
//	keyType, err := GetKeyTypeFromDER(derData)
//	if err != nil {
//		log.Printf("Could not determine key type: %v", err)
//	} else {
//		fmt.Printf("Key type: %s\n", keyType)
//	}
func GetKeyTypeFromDER(derData keypair.DER) (string, error) {
	if privateKey, err := x509.ParsePKCS8PrivateKey(derData); err == nil {
		return getKeyTypeFromInterface(privateKey), nil
	}

	if publicKey, err := x509.ParsePKIXPublicKey(derData); err == nil {
		return getKeyTypeFromInterface(publicKey), nil
	}

	return "", NewFormatError(FormatDER, "unable to determine key type from DER data", nil)
}

// getKeyTypeFromInterface maps Go key types to standardized algorithm names.
// This is an internal utility function used by GetKeyTypeFromDER.
//
// Parameters:
//   - key: Interface containing a parsed cryptographic key
//
// Returns:
//   - String identifier ("RSA", "ECDSA", "Ed25519", or "Unknown")
//
// The function uses type switches to identify the key algorithm from the
// Go types returned by x509 parsing functions.
func getKeyTypeFromInterface(key interface{}) string {
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PrivateKey, ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// EncodedKeyToDER converts an EncodedKey to DER format.
// This function handles format conversion from various input formats to DER.
//
// Parameters:
//   - encodedKey: The encoded key to convert (supports PEM and existing DER)
//
// Returns:
//   - *EncodedKey: New EncodedKey structure with DER format
//   - Error if conversion fails or format is unsupported
//
// Behavior:
//   - If input is already DER format, returns a copy
//   - If input is PEM format, converts to DER
//   - Auto-detects key type if not specified in input
//   - Other formats return an error
//
// Example:
//
//	derKey, err := EncodedKeyToDER(pemEncodedKey)
//	if err != nil {
//		log.Printf("Format conversion failed: %v", err)
//	}
func EncodedKeyToDER(encodedKey *EncodedKey) (*EncodedKey, error) {
	if encodedKey.Format == FormatDER {
		return &EncodedKey{
			Data:    encodedKey.Data,
			Format:  FormatDER,
			KeyType: encodedKey.KeyType,
		}, nil
	}

	if encodedKey.Format == FormatPEM {
		derData, err := ConvertPEMToDER(encodedKey.Data)
		if err != nil {
			return nil, err
		}

		keyType := encodedKey.KeyType
		if keyType == "" {
			keyType, _ = GetKeyTypeFromDER(derData)
		}

		return &EncodedKey{
			Data:    derData,
			Format:  FormatDER,
			KeyType: keyType,
		}, nil
	}

	return nil, NewFormatError(FormatDER, fmt.Sprintf("conversion from %s to DER not yet supported", encodedKey.Format), nil)
}
