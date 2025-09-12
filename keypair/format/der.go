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

// PrivateKeyToDER converts a private key to DER format
func PrivateKeyToDER[T keypair.PrivateKey](privateKey T) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, NewFormatError(FormatDER, "failed to marshal private key to DER", err)
	}
	return derBytes, nil
}

// PublicKeyToDER converts a public key to DER format
func PublicKeyToDER[T keypair.PublicKey](publicKey T) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, NewFormatError(FormatDER, "failed to marshal public key to DER", err)
	}
	return derBytes, nil
}

// ParsePrivateKeyFromDER parses a private key from DER format
func ParsePrivateKeyFromDER[T keypair.PrivateKey](derData []byte) (T, error) {
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

// ParsePublicKeyFromDER parses a public key from DER format
func ParsePublicKeyFromDER[T keypair.PublicKey](derData []byte) (T, error) {
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

// ConvertPEMToDER converts PEM format to DER format
func ConvertPEMToDER(pemData keypair.PEM) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, NewFormatError(FormatDER, "failed to decode PEM block", nil)
	}

	// PEM contains DER data in the Bytes field
	return block.Bytes, nil
}

// ConvertDERToPEM converts DER format to PEM format
func ConvertDERToPEM(derData []byte, keyType string) (keypair.PEM, error) {
	var blockType string

	// Determine PEM block type based on key type
	// We need to detect if it's a private or public key
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

// isPrivateKeyDER attempts to detect if DER data contains a private key
func isPrivateKeyDER(derData []byte) bool {
	// Try to parse as private key first
	_, err := x509.ParsePKCS8PrivateKey(derData)
	return err == nil
}

// GetKeyTypeFromDER determines the key algorithm from DER data
func GetKeyTypeFromDER(derData []byte) (string, error) {
	// Try parsing as private key first
	if privateKey, err := x509.ParsePKCS8PrivateKey(derData); err == nil {
		return getKeyTypeFromInterface(privateKey), nil
	}

	// Try parsing as public key
	if publicKey, err := x509.ParsePKIXPublicKey(derData); err == nil {
		return getKeyTypeFromInterface(publicKey), nil
	}

	return "", NewFormatError(FormatDER, "unable to determine key type from DER data", nil)
}

// getKeyTypeFromInterface determines the algorithm type from a key interface
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

// EncodedKeyToDER converts an EncodedKey to DER format
func EncodedKeyToDER(encodedKey *EncodedKey) (*EncodedKey, error) {
	if encodedKey.Format == FormatDER {
		// Already in DER format
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