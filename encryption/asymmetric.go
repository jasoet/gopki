package encryption

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// AsymmetricEncryptor provides asymmetric encryption operations
type AsymmetricEncryptor struct{}

// NewAsymmetricEncryptor creates a new asymmetric encryptor
func NewAsymmetricEncryptor() *AsymmetricEncryptor {
	return &AsymmetricEncryptor{}
}

// EncryptWithRSA encrypts data using RSA-OAEP
func (e *AsymmetricEncryptor) EncryptWithRSA(data []byte, keyPair *algo.RSAKeyPair, opts EncryptOptions) (*EncryptedData, error) {
	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// RSA-OAEP has data size limitations
	maxDataSize := keyPair.PublicKey.Size() - 2*sha256.Size - 2
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("%w: data size %d exceeds maximum %d for RSA key size %d",
			ErrDataTooLarge, len(data), maxDataSize, keyPair.PublicKey.Size()*8)
	}

	// Encrypt using RSA-OAEP with SHA-256
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, keyPair.PublicKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	return &EncryptedData{
		Algorithm: AlgorithmRSAOAEP,
		Format:    opts.Format,
		Data:      encrypted,
		Timestamp: time.Now(),
		Metadata:  opts.Metadata,
	}, nil
}

// DecryptWithRSA decrypts RSA-OAEP encrypted data
func (e *AsymmetricEncryptor) DecryptWithRSA(encrypted *EncryptedData, keyPair *algo.RSAKeyPair, opts DecryptOptions) ([]byte, error) {
	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != AlgorithmRSAOAEP {
		return nil, fmt.Errorf("expected RSA-OAEP algorithm, got %s", encrypted.Algorithm)
	}

	// Decrypt using RSA-OAEP with SHA-256
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, keyPair.PrivateKey, encrypted.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}

	return decrypted, nil
}

// EncryptWithECDSA encrypts data using ECDH key agreement + AES-GCM
func (e *AsymmetricEncryptor) EncryptWithECDSA(data []byte, keyPair *algo.ECDSAKeyPair, opts EncryptOptions) (*EncryptedData, error) {
	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Convert ECDSA key to ECDH for key agreement
	ecdhPrivateKey, err := keyPair.PrivateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA private key to ECDH: %w", err)
	}

	ecdhPublicKey, err := keyPair.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA public key to ECDH: %w", err)
	}

	// Generate ephemeral key pair for sender
	ephemeralPrivateKey, err := ecdhPrivateKey.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH key agreement
	sharedSecret, err := ephemeralPrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := deriveAESKey(sharedSecret)

	// Encrypt data using AES-GCM
	encryptedData, iv, tag, err := encryptAESGCM(data, aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	// Include ephemeral public key for recipient
	ephemeralPublicKeyBytes, err := x509.MarshalPKIXPublicKey(ephemeralPrivateKey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ephemeral public key: %w", err)
	}

	return &EncryptedData{
		Algorithm:    AlgorithmECDH,
		Format:       opts.Format,
		Data:         encryptedData,
		EncryptedKey: ephemeralPublicKeyBytes, // Store ephemeral public key
		IV:           iv,
		Tag:          tag,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// DecryptWithECDSA decrypts ECDH + AES-GCM encrypted data
func (e *AsymmetricEncryptor) DecryptWithECDSA(encrypted *EncryptedData, keyPair *algo.ECDSAKeyPair, opts DecryptOptions) ([]byte, error) {
	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != AlgorithmECDH {
		return nil, fmt.Errorf("expected ECDH algorithm, got %s", encrypted.Algorithm)
	}

	// Convert ECDSA private key to ECDH
	ecdhPrivateKey, err := keyPair.PrivateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA private key to ECDH: %w", err)
	}

	// Parse ephemeral public key
	ephemeralPublicKeyInterface, err := x509.ParsePKIXPublicKey(encrypted.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	ephemeralECDSAKey, ok := ephemeralPublicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ephemeral key is not ECDSA public key")
	}

	ephemeralECDHKey, err := ephemeralECDSAKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ephemeral ECDSA key to ECDH: %w", err)
	}

	// Perform ECDH key agreement
	sharedSecret, err := ecdhPrivateKey.ECDH(ephemeralECDHKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := deriveAESKey(sharedSecret)

	// Decrypt data using AES-GCM
	decrypted, err := decryptAESGCM(encrypted.Data, aesKey, encrypted.IV, encrypted.Tag)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return decrypted, nil
}

// EncryptWithEd25519 encrypts data using X25519 key agreement + AES-GCM
func (e *AsymmetricEncryptor) EncryptWithEd25519(data []byte, keyPair *algo.Ed25519KeyPair, opts EncryptOptions) (*EncryptedData, error) {
	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Convert Ed25519 key to X25519 for key agreement
	x25519PublicKey := make([]byte, 32)
	copy(x25519PublicKey, keyPair.PublicKey)

	// Create ECDH X25519 keys
	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(x25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 public key: %w", err)
	}

	// Generate ephemeral key pair
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}

	// Perform X25519 key agreement
	sharedSecret, err := ephemeralPrivateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := deriveAESKey(sharedSecret)

	// Encrypt data using AES-GCM
	encryptedData, iv, tag, err := encryptAESGCM(data, aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	return &EncryptedData{
		Algorithm:    AlgorithmX25519,
		Format:       opts.Format,
		Data:         encryptedData,
		EncryptedKey: ephemeralPrivateKey.PublicKey().Bytes(), // Store ephemeral public key
		IV:           iv,
		Tag:          tag,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// DecryptWithEd25519 decrypts X25519 + AES-GCM encrypted data
func (e *AsymmetricEncryptor) DecryptWithEd25519(encrypted *EncryptedData, keyPair *algo.Ed25519KeyPair, opts DecryptOptions) ([]byte, error) {
	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != AlgorithmX25519 {
		return nil, fmt.Errorf("expected X25519 algorithm, got %s", encrypted.Algorithm)
	}

	// Convert Ed25519 key to X25519
	x25519PrivateKey := ed25519.PrivateKey(keyPair.PrivateKey).Seed()

	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(x25519PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key: %w", err)
	}

	// Parse ephemeral public key
	ephemeralPublicKey, err := curve.NewPublicKey(encrypted.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Perform X25519 key agreement
	sharedSecret, err := privateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	// Derive AES key from shared secret
	aesKey := deriveAESKey(sharedSecret)

	// Decrypt data using AES-GCM
	decrypted, err := decryptAESGCM(encrypted.Data, aesKey, encrypted.IV, encrypted.Tag)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return decrypted, nil
}

// Generic encryption function that dispatches to the appropriate algorithm
func (e *AsymmetricEncryptor) Encrypt(data []byte, keyPair any, opts EncryptOptions) (*EncryptedData, error) {
	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		return e.EncryptWithRSA(data, kp, opts)
	case *algo.ECDSAKeyPair:
		return e.EncryptWithECDSA(data, kp, opts)
	case *algo.Ed25519KeyPair:
		return e.EncryptWithEd25519(data, kp, opts)
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// Generic decryption function that dispatches to the appropriate algorithm
func (e *AsymmetricEncryptor) Decrypt(encrypted *EncryptedData, keyPair any, opts DecryptOptions) ([]byte, error) {
	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		return e.DecryptWithRSA(encrypted, kp, opts)
	case *algo.ECDSAKeyPair:
		return e.DecryptWithECDSA(encrypted, kp, opts)
	case *algo.Ed25519KeyPair:
		return e.DecryptWithEd25519(encrypted, kp, opts)
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", keyPair)
	}
}

// EncryptForPublicKey encrypts data for a specific public key
func (e *AsymmetricEncryptor) EncryptForPublicKey(data []byte, publicKey any, opts EncryptOptions) (*EncryptedData, error) {
	// This requires generating an ephemeral key pair and using it for encryption
	// The implementation depends on the public key type
	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		// For RSA, we can encrypt directly with the public key
		maxDataSize := pk.Size() - 2*sha256.Size - 2
		if len(data) > maxDataSize {
			return nil, fmt.Errorf("%w: data size %d exceeds maximum %d for RSA key size %d",
				ErrDataTooLarge, len(data), maxDataSize, pk.Size()*8)
		}

		encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, data, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
		}

		return &EncryptedData{
			Algorithm: AlgorithmRSAOAEP,
			Format:    opts.Format,
			Data:      encrypted,
			Timestamp: time.Now(),
			Metadata:  opts.Metadata,
		}, nil

	case *ecdsa.PublicKey, ed25519.PublicKey:
		// For ECDSA and Ed25519, we need key agreement which requires both keys
		return nil, fmt.Errorf("ECDH/X25519 encryption requires a key pair, not just a public key")

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// EncryptWithCertificate encrypts data using a certificate's public key
func (e *AsymmetricEncryptor) EncryptWithCertificate(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	// Extract public key from certificate and encrypt
	publicKey := certificate.Certificate.PublicKey
	return e.EncryptForPublicKey(data, publicKey, opts)
}

// DecryptWithPrivateKey decrypts data using a private key (not implemented for asymmetric)
func (e *AsymmetricEncryptor) DecryptWithPrivateKey(encrypted *EncryptedData, privateKey any, opts DecryptOptions) ([]byte, error) {
	return nil, fmt.Errorf("DecryptWithPrivateKey not supported for asymmetric encryption - use Decrypt with key pair instead")
}

// SupportedAlgorithms returns the algorithms supported by this encryptor
func (e *AsymmetricEncryptor) SupportedAlgorithms() []EncryptionAlgorithm {
	return []EncryptionAlgorithm{
		AlgorithmRSAOAEP,
		AlgorithmECDH,
		AlgorithmX25519,
	}
}

// Type-safe wrapper functions using generic constraints

// EncryptAsymmetric provides type-safe asymmetric encryption using generic constraints
func EncryptAsymmetric[T keypair.KeyPair](data []byte, keyPair T, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewAsymmetricEncryptor()
	return encryptor.Encrypt(data, keyPair, opts)
}

// DecryptAsymmetric provides type-safe asymmetric decryption using generic constraints
func DecryptAsymmetric[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, opts DecryptOptions) ([]byte, error) {
	encryptor := NewAsymmetricEncryptor()
	return encryptor.Decrypt(encrypted, keyPair, opts)
}

// EncryptForPublicKeyTyped provides type-safe public key encryption using generic constraints
func EncryptForPublicKeyTyped[T keypair.PublicKey](data []byte, publicKey T, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewAsymmetricEncryptor()
	return encryptor.EncryptForPublicKey(data, publicKey, opts)
}

// EncryptWithCertificateTyped provides type-safe certificate-based encryption
func EncryptWithCertificateTyped(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewAsymmetricEncryptor()
	return encryptor.EncryptWithCertificate(data, certificate, opts)
}
