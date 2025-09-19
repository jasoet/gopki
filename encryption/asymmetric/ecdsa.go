package asymmetric

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/keypair/algo"
)

// EncryptWithECDSA encrypts data using ECDH key agreement + AES-GCM.
//
// This function uses elliptic curve Diffie-Hellman (ECDH) key agreement to establish
// a shared secret, then uses that secret to derive an AES key for data encryption.
// An ephemeral key pair is generated for each encryption operation to ensure forward secrecy.
//
// Process:
//  1. Convert ECDSA keys to ECDH format
//  2. Generate ephemeral sender key pair
//  3. Perform ECDH key agreement to get shared secret
//  4. Derive AES-256 key from shared secret
//  5. Encrypt data with AES-GCM using derived key
//  6. Include ephemeral public key in result for recipient
//
// Parameters:
//   - data: The plaintext data to encrypt (no size limitations)
//   - keyPair: The ECDSA key pair (public key used for key agreement)
//   - opts: Encryption options (algorithm will be set to AlgorithmECDH)
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data with ECDH algorithm metadata
//   - error: Any error that occurred during key agreement or encryption
//
// Security properties:
//   - Perfect forward secrecy through ephemeral keys
//   - Authenticated encryption via AES-GCM
//   - Protection against key reuse attacks
//
// Example:
//
//	ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	data := []byte("large amount of data")  // No size limitations
//
//	encrypted, err := asymmetric.EncryptWithECDSA(data, ecdsaKeys, opts)
//	if err != nil {
//		log.Fatal("ECDSA encryption failed:", err)
//	}
func EncryptWithECDSA(data []byte, keyPair *algo.ECDSAKeyPair, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if err := encryption.ValidateEncryptOptions(opts); err != nil {
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
	ephemeralPublicKeyBytes := ephemeralPrivateKey.PublicKey().Bytes()

	return &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmECDH,
		Format:       opts.Format,
		Data:         encryptedData,
		EncryptedKey: ephemeralPublicKeyBytes, // Store ephemeral public key
		IV:           iv,
		Tag:          tag,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// DecryptWithECDSA decrypts ECDH + AES-GCM encrypted data.
//
// This function reverses the ECDSA encryption process by:
//  1. Converting the recipient's ECDSA private key to ECDH format
//  2. Extracting the sender's ephemeral public key from encrypted data
//  3. Performing ECDH key agreement to recover the shared secret
//  4. Deriving the same AES key used for encryption
//  5. Decrypting the data using AES-GCM
//
// Parameters:
//   - encrypted: The encrypted data to decrypt (must contain ephemeral key)
//   - keyPair: The ECDSA key pair (private key used for key agreement)
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error that occurred during key agreement or decryption
//
// Example:
//
//	plaintext, err := asymmetric.DecryptWithECDSA(encrypted, ecdsaKeys, opts)
func DecryptWithECDSA(encrypted *encryption.EncryptedData, keyPair *algo.ECDSAKeyPair, opts encryption.DecryptOptions) ([]byte, error) {
	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != encryption.AlgorithmECDH {
		return nil, fmt.Errorf("expected ECDH algorithm, got %s", encrypted.Algorithm)
	}

	// Convert ECDSA private key to ECDH
	ecdhPrivateKey, err := keyPair.PrivateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA private key to ECDH: %w", err)
	}

	// Parse ephemeral public key from ECDH bytes
	curve := ecdhPrivateKey.Curve()
	ephemeralECDHKey, err := curve.NewPublicKey(encrypted.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
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
