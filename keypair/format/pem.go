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

// ParsePrivateKeyFromPEM parses a private key from PEM-encoded data with type safety.
// The function uses generics to ensure the returned key matches the expected type.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - pemData: PEM-encoded private key data in PKCS#8 format
//
// Returns the parsed private key or an error if parsing fails or type doesn't match.
//
// Example:
//
//	rsaPrivateKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse RSA private key: %v", err)
//	}
func ParsePrivateKeyFromPEM[T keypair.PrivateKey](pemData keypair.PEM) (T, error) {
	var zero T

	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, NewFormatError(FormatPEM, "failed to decode PEM block", nil)
	}

	if block.Type != "PRIVATE KEY" {
		return zero, NewFormatError(FormatPEM, "PEM block is not a private key", nil)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return zero, NewFormatError(FormatPEM, "failed to parse private key", err)
	}

	typedKey, ok := privateKey.(T)
	if !ok {
		return zero, NewFormatError(FormatPEM, "private key is not of expected type", nil)
	}

	return typedKey, nil
}

// PrivateKeyFromPEM attempts to parse a private key from PEM data, auto-detecting the algorithm.
// This function tries all supported algorithms (RSA, ECDSA, Ed25519) and returns the first match.
// It's a convenience function that provides algorithm detection without requiring the caller
// to know the key type in advance.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - pemData: PEM-encoded private key data
//
// Returns:
//   - The parsed private key of the specified type
//   - Algorithm name ("RSA", "ECDSA", or "Ed25519")
//   - Error if parsing fails for all algorithms or type doesn't match
//
// The function attempts to parse the key with each supported algorithm until one succeeds.
// It then performs type assertion to ensure the result matches the expected type parameter.
//
// Example:
//
//	privateKey, algorithm, err := PrivateKeyFromPEM[*rsa.PrivateKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse private key: %v", err)
//	} else {
//		log.Printf("Parsed %s private key", algorithm)
//	}
func PrivateKeyFromPEM[T keypair.PrivateKey](pemData keypair.PEM) (T, string, error) {
	var zero T

	if rsaKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		if typedKey, ok := any(rsaKey).(T); ok {
			return typedKey, "RSA", nil
		}
	}

	if ecdsaKey, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		if typedKey, ok := any(ecdsaKey).(T); ok {
			return typedKey, "ECDSA", nil
		}
	}

	if ed25519Key, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		if typedKey, ok := any(ed25519Key).(T); ok {
			return typedKey, "Ed25519", nil
		}
	}

	return zero, "", NewFormatError(FormatPEM, "unable to parse private key: unsupported algorithm or invalid format", nil)
}


// ParsePublicKeyFromPEM parses a public key from PEM-encoded data with type safety.
// The function uses generics to ensure the returned key matches the expected type.
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - pemData: PEM-encoded public key data
//
// Returns the parsed public key or an error if parsing fails or type doesn't match.
//
// Example:
//
//	rsaPublicKey, err := ParsePublicKeyFromPEM[*rsa.PublicKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse RSA public key: %v", err)
//	}
func ParsePublicKeyFromPEM[T keypair.PublicKey](pemData keypair.PEM) (T, error) {
	var zero T

	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, NewFormatError(FormatPEM, "failed to decode PEM block", nil)
	}

	if block.Type != "PUBLIC KEY" {
		return zero, NewFormatError(FormatPEM, "PEM block is not a public key", nil)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return zero, NewFormatError(FormatPEM, "failed to parse public key", err)
	}

	typedKey, ok := publicKey.(T)
	if !ok {
		return zero, NewFormatError(FormatPEM, "public key is not of expected type", nil)
	}

	return typedKey, nil
}

// GetKeyTypeFromPEM determines the cryptographic algorithm of a PEM-encoded key.
// The function attempts to parse the key as both private and public key formats.
//
// Parameters:
//   - pemData: PEM-encoded key data
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
//	keyType, err := GetKeyTypeFromPEM(pemData)
//	if err != nil {
//		log.Printf("Could not determine key type: %v", err)
//	} else {
//		fmt.Printf("Key type: %s\n", keyType)
//	}
func GetKeyTypeFromPEM(pemData keypair.PEM) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", NewFormatError(FormatPEM, "failed to decode PEM block", nil)
	}

	// Try to parse as private key first
	if block.Type == "PRIVATE KEY" {
		if privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return getKeyTypeFromInterface(privateKey), nil
		}
	}

	// Try to parse as public key
	if block.Type == "PUBLIC KEY" {
		if publicKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			return getKeyTypeFromInterface(publicKey), nil
		}
	}

	return "", NewFormatError(FormatPEM, "unable to determine key type from PEM data", nil)
}


// isPrivateKeyPEM determines if PEM data contains a private key by checking the block type.
// This is an internal utility function used for automatic key type detection.
//
// Parameters:
//   - pemData: PEM-encoded data
//
// Returns:
//   - true if the PEM block type is "PRIVATE KEY", false otherwise
//
// The function checks the PEM block type without parsing the actual key data.
func isPrivateKeyPEM(pemData keypair.PEM) bool {
	block, _ := pem.Decode(pemData)
	return block != nil && block.Type == "PRIVATE KEY"
}

// ValidatePEMFormat validates that the provided data is in proper PEM format
// and contains a supported key type (PUBLIC KEY or PRIVATE KEY).
//
// It returns an error if:
//   - The data is not valid PEM format
//   - The PEM block type is not PUBLIC KEY or PRIVATE KEY
//
// Example:
//
//	err := ValidatePEMFormat(pemData)
//	if err != nil {
//		log.Printf("Invalid PEM format: %v", err)
//	}
func ValidatePEMFormat(pemData keypair.PEM) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return NewFormatError(FormatPEM, "invalid PEM format", nil)
	}

	if block.Type != "PUBLIC KEY" && block.Type != "PRIVATE KEY" {
		return NewFormatError(FormatPEM, fmt.Sprintf("unsupported PEM type: %s", block.Type), nil)
	}

	return nil
}

// EncodedKeyToPEM converts an EncodedKey to PEM format.
// This function handles format conversion from various input formats to PEM.
//
// Parameters:
//   - encodedKey: The encoded key to convert (supports DER and existing PEM)
//
// Returns:
//   - *EncodedKey: New EncodedKey structure with PEM format
//   - Error if conversion fails or format is unsupported
//
// Behavior:
//   - If input is already PEM format, returns a copy
//   - If input is DER format, converts to PEM
//   - Auto-detects key type if not specified in input
//   - Other formats return an error
//
// Example:
//
//	pemKey, err := EncodedKeyToPEM(derEncodedKey)
//	if err != nil {
//		log.Printf("Format conversion failed: %v", err)
//	}
func EncodedKeyToPEM(encodedKey *EncodedKey) (*EncodedKey, error) {
	if encodedKey.Format == FormatPEM {
		return &EncodedKey{
			Data:    encodedKey.Data,
			Format:  FormatPEM,
			KeyType: encodedKey.KeyType,
		}, nil
	}

	if encodedKey.Format == FormatDER {
		pemData, err := ConvertDERToPEM(encodedKey.Data, encodedKey.KeyType)
		if err != nil {
			return nil, err
		}

		keyType := encodedKey.KeyType
		if keyType == "" {
			keyType, _ = GetKeyTypeFromPEM(pemData)
		}

		return &EncodedKey{
			Data:    pemData,
			Format:  FormatPEM,
			KeyType: keyType,
		}, nil
	}

	return nil, NewFormatError(FormatPEM, fmt.Sprintf("conversion from %s to PEM not yet supported", encodedKey.Format), nil)
}