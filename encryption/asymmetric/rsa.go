package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

// EncryptWithRSA encrypts data using RSA-OAEP (Optimal Asymmetric Encryption Padding).
//
// This function provides direct RSA encryption using OAEP padding with SHA-256 hash
// function. RSA-OAEP is semantically secure and prevents various padding oracle
// attacks that affect older RSA padding schemes.
//
// Data size limitations:
//
//	For a k-bit RSA key, the maximum plaintext size is approximately:
//	- 2048-bit key: ~190 bytes
//	- 3072-bit key: ~318 bytes
//	- 4096-bit key: ~446 bytes
//
// Parameters:
//   - data: The plaintext data to encrypt (must fit within RSA size limits)
//   - keyPair: The RSA key pair (public key will be used for encryption)
//   - opts: Encryption options (algorithm will be set to AlgorithmRSAOAEP)
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data with RSA-OAEP algorithm metadata
//   - error: encryption.ErrDataTooLarge if data exceeds RSA capacity, or other encryption errors
//
// Security properties:
//   - Semantic security: identical plaintexts produce different ciphertexts
//   - Chosen ciphertext security under standard assumptions
//   - Protection against padding oracle attacks
//
// Example:
//
//	rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
//	data := []byte("small secret message")  // Must be ≤190 bytes for 2048-bit key
//
//	encrypted, err := asymmetric.EncryptWithRSA(data, rsaKeys, opts)
//	if err != nil {
//		log.Fatal("RSA encryption failed:", err)
//	}
func EncryptWithRSA(data []byte, keyPair *algo.RSAKeyPair, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if err := encryption.ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// RSA-OAEP has data size limitations
	maxDataSize := keyPair.PublicKey.Size() - 2*sha256.Size - 2
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("%w: data size %d exceeds maximum %d for RSA key size %d",
			encryption.ErrDataTooLarge, len(data), maxDataSize, keyPair.PublicKey.Size()*8)
	}

	// Encrypt using RSA-OAEP with SHA-256
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, keyPair.PublicKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	return &encryption.EncryptedData{
		Algorithm: encryption.AlgorithmRSAOAEP,
		Format:    opts.Format,
		Data:      encrypted,
		Timestamp: time.Now(),
		Metadata:  opts.Metadata,
	}, nil
}

// DecryptWithRSA decrypts RSA-OAEP encrypted data.
//
// Parameters:
//   - encrypted: The encrypted data to decrypt
//   - keyPair: The RSA key pair (private key will be used for decryption)
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error that occurred during decryption
//
// Example:
//
//	plaintext, err := asymmetric.DecryptWithRSA(encrypted, rsaKeys, opts)
func DecryptWithRSA(encrypted *encryption.EncryptedData, keyPair *algo.RSAKeyPair, opts encryption.DecryptOptions) ([]byte, error) {
	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != encryption.AlgorithmRSAOAEP {
		return nil, fmt.Errorf("expected RSA-OAEP algorithm, got %s", encrypted.Algorithm)
	}

	// Decrypt using RSA-OAEP with SHA-256
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, keyPair.PrivateKey, encrypted.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}

	return decrypted, nil
}
