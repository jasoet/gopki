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
	"path/filepath"
)

type Param interface {
	algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

type KeyPair interface {
	*algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

type PEM []byte

func ValidatePEMFormat(pemData PEM) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "PRIVATE KEY" {
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return nil
}

func GenerateKeyPair[T Param, K KeyPair](param T) (K, error) {
	var zero K
	switch par := any(param).(type) {
	case algo.KeySize:
		kp, err := algo.GenerateRSAKeyPair(par)
		if err != nil {
			return zero, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
		return any(kp).(K), nil
	case algo.ECDSACurve:
		kp, err := algo.GenerateECDSAKeyPair(par)
		if err != nil {
			return zero, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}
		return any(kp).(K), nil
	case algo.Ed25519Config:
		kp, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			return zero, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
		}
		return any(kp).(K), nil
	default:
		return zero, fmt.Errorf("unsupported parameter type")
	}
}

func ParsePublicKeyFromPEM[T PublicKey](pemData PEM) (T, error) {
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

func ParsePrivateKeyFromPEM[T PrivateKey](pemData PEM) (T, error) {
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

func PrivateKeyToPEM[T PrivateKey](privateKey T) (PEM, error) {
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

func PublicKeyToPEM[T PublicKey](publicKey T) (PEM, error) {
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

func PrivateKeyFromPEM[T PrivateKey](pemData PEM) (T, string, error) {
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

	return zero, "", fmt.Errorf("unable to parse private key: unsupported algorithm or invalid format")
}

func KeyPairToFiles[T KeyPair](keyPair T, privateFile, publicFile string) error {
	var privateKeyPEM, publicKeyPEM PEM
	var err error

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA public key to PEM: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA public key to PEM: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(kp.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 public key to PEM: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	if err := savePEMToFile(privateKeyPEM, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := savePEMToFile(publicKeyPEM, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

func savePEMToFile(pemData PEM, filename string) error {
	dir := filepath.Dir(filename)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if _, err := os.Stat(filename); err == nil {
		file, err := os.OpenFile(filename, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("no write permission for existing file %s: %w", filename, err)
		}
		file.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check file status %s: %w", filename, err)
	}

	if err := os.WriteFile(filename, pemData, 0600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}
