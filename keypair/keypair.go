package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jasoet/gopki/keypair/algo"
	"os"
)

type KeyPair interface {
	*algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

func ParsePublicKeyFromPEM[T PublicKey](pemData []byte) (T, error) {
	var zero T

	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return zero, fmt.Errorf("PEM block is not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse public key: %w", err)
	}

	typedKey, ok := publicKey.(T)
	if !ok {
		return zero, fmt.Errorf("public key is not of expected type")
	}

	return typedKey, nil
}

func ParsePrivateKeyFromPEM[T PrivateKey](pemData []byte) (T, error) {
	var zero T

	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return zero, fmt.Errorf("PEM block is not a private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse private key: %w", err)
	}

	typedKey, ok := privateKey.(T)
	if !ok {
		return zero, fmt.Errorf("private key is not of expected type")
	}

	return typedKey, nil
}

func ValidatePEMFormat(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "PRIVATE KEY" {
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return nil
}

func GenerateRSAKeyPair(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	keyPair, err := algo.GenerateRSAKeyPair(keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return keyPair.PrivateKey, keyPair.PublicKey, nil
}

func GenerateECDSAKeyPair(curve algo.ECDSACurve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	keyPair, err := algo.GenerateECDSAKeyPair(curve)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	return keyPair.PrivateKey, keyPair.PublicKey, nil
}

func GenerateEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {

	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	return keyPair.PrivateKey, keyPair.PublicKey, nil
}

func PrivateKeyToPEM[T PrivateKey](privateKey T) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

func PublicKeyToPEM[T PublicKey](publicKey T) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

func GetPublicKey[TPriv PrivateKey, TPub PublicKey](privateKey TPriv) (TPub, error) {
	var zero TPub

	switch priv := any(privateKey).(type) {
	case *rsa.PrivateKey:
		if pub, ok := any(&priv.PublicKey).(TPub); ok {
			return pub, nil
		}
	case *ecdsa.PrivateKey:
		if pub, ok := any(&priv.PublicKey).(TPub); ok {
			return pub, nil
		}
	case ed25519.PrivateKey:
		if pub, ok := any(priv.Public().(ed25519.PublicKey)).(TPub); ok {
			return pub, nil
		}
	}

	return zero, fmt.Errorf("unsupported key type or type mismatch")
}

func ConvertKeyPairToPEM[TPriv PrivateKey, TPub PublicKey](privateKey TPriv, publicKey TPub) (privatePEM, publicPEM []byte, err error) {
	privatePEM, err = PrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert private key to PEM: %w", err)
	}

	publicPEM, err = PublicKeyToPEM(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	return privatePEM, publicPEM, nil
}

func DetectAlgorithmFromPEM(pemData []byte) (string, error) {
	if _, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		return "RSA", nil
	}

	if _, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		return "ECDSA", nil
	}

	if _, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		return "Ed25519", nil
	}

	return "", fmt.Errorf("unable to detect algorithm: unsupported or invalid key format")
}

func ParseAnyPrivateKeyFromPEM(pemData []byte) (privateKey interface{}, algorithm string, err error) {
	// Try RSA
	if rsaKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		return rsaKey, "RSA", nil
	}

	// Try ECDSA
	if ecdsaKey, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		return ecdsaKey, "ECDSA", nil
	}

	// Try Ed25519
	if ed25519Key, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		return ed25519Key, "Ed25519", nil
	}

	return nil, "", fmt.Errorf("unable to parse private key: unsupported algorithm or invalid format")
}

func SaveKeyPairToFiles[TPriv PrivateKey, TPub PublicKey](privateKey TPriv, publicKey TPub, privateFile, publicFile string) error {
	privatePEM, publicPEM, err := ConvertKeyPairToPEM(privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert keys to PEM: %w", err)
	}

	if err := savePEMToFile(privatePEM, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := savePEMToFile(publicPEM, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// Helper function for saving PEM to file
func savePEMToFile(pemData []byte, filename string) error {
	return os.WriteFile(filename, pemData, 0600)
}
