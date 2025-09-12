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

func PrivateKeyToDER[T keypair.PrivateKey](privateKey T) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, NewFormatError(FormatDER, "failed to marshal private key to DER", err)
	}
	return derBytes, nil
}

func PublicKeyToDER[T keypair.PublicKey](publicKey T) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, NewFormatError(FormatDER, "failed to marshal public key to DER", err)
	}
	return derBytes, nil
}

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

func ConvertPEMToDER(pemData keypair.PEM) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, NewFormatError(FormatDER, "failed to decode PEM block", nil)
	}

	return block.Bytes, nil
}

func ConvertDERToPEM(derData []byte, keyType string) (keypair.PEM, error) {
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

func isPrivateKeyDER(derData []byte) bool {
	_, err := x509.ParsePKCS8PrivateKey(derData)
	return err == nil
}

func GetKeyTypeFromDER(derData []byte) (string, error) {
	if privateKey, err := x509.ParsePKCS8PrivateKey(derData); err == nil {
		return getKeyTypeFromInterface(privateKey), nil
	}

	if publicKey, err := x509.ParsePKIXPublicKey(derData); err == nil {
		return getKeyTypeFromInterface(publicKey), nil
	}

	return "", NewFormatError(FormatDER, "unable to determine key type from DER data", nil)
}

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
