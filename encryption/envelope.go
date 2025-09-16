// File envelope.go implements hybrid envelope encryption for efficient encryption
// of large data sets using a combination of symmetric and asymmetric cryptography.
//
// Envelope encryption (also known as hybrid encryption) is a cryptographic technique
// that combines the speed of symmetric encryption with the key distribution benefits
// of asymmetric encryption. It's the recommended approach for encrypting large amounts
// of data or when you need to encrypt for multiple recipients.
//
// How envelope encryption works:
//   1. Generate a random symmetric encryption key (Data Encryption Key - DEK)
//   2. Encrypt the actual data with the DEK using AES-GCM
//   3. Encrypt the DEK with the recipient's public key (Key Encryption Key - KEK)
//   4. Return both the encrypted data and the encrypted DEK
//
// Advantages:
//   - Efficient for large data (no size limitations)
//   - Can encrypt for multiple recipients by encrypting DEK with each recipient's key
//   - Provides perfect forward secrecy when using ephemeral keys
//   - Scales well with data size (only DEK encryption time scales with recipients)
//
// Security properties:
//   - Data confidentiality through AES-GCM symmetric encryption
//   - Key confidentiality through asymmetric encryption of the DEK
//   - Data integrity and authenticity through AES-GCM authentication
//   - Fresh DEK for each encryption operation
//
// Use cases:
//   - Encrypting files larger than RSA key size limits
//   - Multi-recipient encryption scenarios
//   - Cloud storage encryption
//   - Secure messaging systems
//   - Database field encryption
package encryption

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// EnvelopeEncryptor implements hybrid envelope encryption combining the efficiency
// of symmetric encryption with the key distribution benefits of asymmetric encryption.
//
// This encryptor automatically:
//   - Generates a fresh AES-256 Data Encryption Key (DEK) for each operation
//   - Encrypts the actual data with AES-GCM using the DEK
//   - Encrypts the DEK with the recipient's public key using appropriate asymmetric algorithm
//   - Combines both encrypted components into a single EncryptedData structure
//
// The encryptor supports all GoPKI key types:
//   - RSA keys: DEK encrypted with RSA-OAEP
//   - ECDSA keys: DEK encrypted using ECDH key agreement + AES-GCM
//   - Ed25519 keys: DEK encrypted using X25519 key agreement + AES-GCM
//
// Performance characteristics:
//   - Encryption time scales linearly with data size (through AES-GCM)
//   - Key encryption time is constant regardless of data size
//   - Memory usage is proportional to data size (streaming possible)
//   - Optimal for data larger than ~1KB
type EnvelopeEncryptor struct {
	asymmetric *AsymmetricEncryptor
	symmetric  *SymmetricEncryptor
}

// NewEnvelopeEncryptor creates a new envelope encryptor instance.
//
// The encryptor is initialized with both asymmetric and symmetric encryptors
// to handle the hybrid encryption process efficiently.
//
// Returns:
//   - *EnvelopeEncryptor: A new encryptor ready for envelope encryption operations
//
// Example:
//
//	encryptor := NewEnvelopeEncryptor()
//	largeData := make([]byte, 1024*1024)  // 1MB data
//	encrypted, err := encryptor.Encrypt(largeData, keyPair, opts)
func NewEnvelopeEncryptor() *EnvelopeEncryptor {
	return &EnvelopeEncryptor{
		asymmetric: NewAsymmetricEncryptor(),
		symmetric:  NewSymmetricEncryptor(),
	}
}

// Encrypt encrypts data using envelope encryption (hybrid approach) for efficient
// handling of data of any size with any supported key type.
//
// This method implements the complete envelope encryption workflow:
//   1. Generates a fresh 256-bit AES key (Data Encryption Key - DEK)
//   2. Encrypts the plaintext data with AES-GCM using the DEK
//   3. Encrypts the DEK using the appropriate asymmetric algorithm for the key type
//   4. Combines encrypted data and encrypted DEK into a single structure
//
// Algorithm selection is automatic based on key type:
//   - RSA keys: DEK encrypted with RSA-OAEP
//   - ECDSA keys: DEK encrypted via ECDH key agreement + AES-GCM
//   - Ed25519 keys: DEK encrypted via X25519 key agreement + AES-GCM
//
// Parameters:
//   - data: The plaintext data to encrypt (any size supported)
//   - keyPair: The recipient's key pair (public key used for DEK encryption)
//   - opts: Encryption options (algorithm will be set to AlgorithmEnvelope)
//
// Returns:
//   - *EncryptedData: Encrypted data with envelope algorithm and combined payload
//   - error: Any error during DEK generation, data encryption, or key encryption
//
// Performance benefits:
//   - No data size limitations (unlike direct RSA encryption)
//   - Linear scaling with data size (O(n) instead of O(n²) for repeated asymmetric encryption)
//   - Efficient memory usage (can be adapted for streaming)
//   - Fast decryption (single DEK decryption + fast AES-GCM data decryption)
//
// Security properties:
//   - Fresh DEK for each encryption ensures semantic security
//   - AES-GCM provides authenticated encryption of data
//   - Asymmetric encryption protects DEK confidentiality
//   - No key reuse across different encryption operations
//
// Example:
//
//	encryptor := NewEnvelopeEncryptor()
//
//	// Works with any key type
//	rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
//	ecdsaKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
//
//	// Encrypt large data efficiently
//	largeFile := make([]byte, 10*1024*1024)  // 10MB file
//	encrypted, err := encryptor.Encrypt(largeFile, rsaKeys, opts)
//	if err != nil {
//		log.Fatal("Envelope encryption failed:", err)
//	}
//
//	// The encrypted data contains both the encrypted file and encrypted DEK
func (e *EnvelopeEncryptor) Encrypt(data []byte, keyPair any, opts EncryptOptions) (*EncryptedData, error) {
	if err := ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Generate random AES-256 key for data encryption
	aesKey, err := GenerateAESKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	symmetricOpts := EncryptOptions{
		Algorithm: AlgorithmAESGCM,
		Format:    opts.Format,
		Metadata:  make(map[string]interface{}),
	}

	encryptedData, err := e.symmetric.EncryptAESGCM(data, aesKey, symmetricOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with AES: %w", err)
	}

	// Encrypt AES key with recipient's public key
	keyEncryptOpts := EncryptOptions{
		Algorithm: GetAlgorithmForKeyType(getKeyType(keyPair)),
		Format:    FormatCMS, // Use CMS format for standards compliance
		Metadata:  make(map[string]interface{}),
	}

	encryptedKey, err := e.asymmetric.Encrypt(aesKey, keyPair, keyEncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Create recipient info with complete encrypted key data
	recipient := &RecipientInfo{
		EncryptedKey:           encryptedKey.Data,
		KeyEncryptionAlgorithm: encryptedKey.Algorithm,
		EphemeralKey:           encryptedKey.EncryptedKey, // For ECDSA/Ed25519
		KeyIV:                  encryptedKey.IV,
		KeyTag:                 encryptedKey.Tag,
	}

	// Create envelope encrypted data
	envelope := &EncryptedData{
		Algorithm:    AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: encryptedKey.Data, // Keep for backward compatibility
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
		Recipients:   []*RecipientInfo{recipient},
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}

	// Add certificate to recipient info if requested
	if opts.IncludeCertificate {
		// Certificate info would be added here if we had access to it
		// For now, the recipient info is already populated above
	}

	return envelope, nil
}

// Decrypt decrypts envelope-encrypted data
func (e *EnvelopeEncryptor) Decrypt(encrypted *EncryptedData, keyPair any, opts DecryptOptions) ([]byte, error) {
	if err := ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != AlgorithmEnvelope {
		return nil, fmt.Errorf("expected envelope algorithm, got %s", encrypted.Algorithm)
	}

	// Decrypt AES key using recipient's private key
	keyDecryptOpts := DecryptOptions{
		ExpectedAlgorithm: GetAlgorithmForKeyType(getKeyType(keyPair)),
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: make(map[string]interface{}),
	}

	var aesKey []byte
	var err error

	// Try to use recipient info if available (new format with ECDSA/Ed25519 support)
	if len(encrypted.Recipients) > 0 {
		recipient := encrypted.Recipients[0] // Use first recipient
		keyEncryptedData := &EncryptedData{
			Algorithm:    recipient.KeyEncryptionAlgorithm,
			Format:       FormatCMS, // Use CMS format for standards compliance
			Data:         recipient.EncryptedKey,
			EncryptedKey: recipient.EphemeralKey, // Ephemeral key for ECDSA/Ed25519
			IV:           recipient.KeyIV,
			Tag:          recipient.KeyTag,
		}

		aesKey, err = e.asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
	} else {
		// Fallback to legacy format (RSA only)
		keyEncryptedData := &EncryptedData{
			Algorithm: GetAlgorithmForKeyType(getKeyType(keyPair)),
			Format:    FormatCMS, // Use CMS format for standards compliance
			Data:      encrypted.EncryptedKey,
		}

		aesKey, err = e.asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// Decrypt data using recovered AES key
	dataEncryptedData := &EncryptedData{
		Algorithm: AlgorithmAESGCM,
		Format:    encrypted.Format,
		Data:      encrypted.Data,
		IV:        encrypted.IV,
		Tag:       encrypted.Tag,
	}

	dataDecryptOpts := DecryptOptions{
		ExpectedAlgorithm: AlgorithmAESGCM,
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: opts.ValidationOptions,
	}

	plaintext, err := e.symmetric.DecryptAESGCM(dataEncryptedData, aesKey, dataDecryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with AES: %w", err)
	}

	return plaintext, nil
}

// EncryptForPublicKey encrypts data for a specific public key using envelope encryption
func (e *EnvelopeEncryptor) EncryptForPublicKey(data []byte, publicKey any, opts EncryptOptions) (*EncryptedData, error) {
	// Generate random AES-256 key for data encryption
	aesKey, err := GenerateAESKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	symmetricOpts := EncryptOptions{
		Algorithm: AlgorithmAESGCM,
		Format:    opts.Format,
		Metadata:  make(map[string]interface{}),
	}

	encryptedData, err := e.symmetric.EncryptAESGCM(data, aesKey, symmetricOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with AES: %w", err)
	}

	// Encrypt AES key with recipient's public key
	keyEncryptOpts := EncryptOptions{
		Algorithm: GetAlgorithmForKeyType(getPublicKeyType(publicKey)),
		Format:    FormatCMS,
		Metadata:  make(map[string]interface{}),
	}

	encryptedKey, err := e.asymmetric.EncryptForPublicKey(aesKey, publicKey, keyEncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Create recipient info with complete encrypted key data (same as multi-recipient flow)
	recipient := &RecipientInfo{
		EncryptedKey:           encryptedKey.Data,
		KeyEncryptionAlgorithm: encryptedKey.Algorithm,
		EphemeralKey:           encryptedKey.EncryptedKey, // For ECDSA/Ed25519
		KeyIV:                  encryptedKey.IV,
		KeyTag:                 encryptedKey.Tag,
	}

	return &EncryptedData{
		Algorithm:    AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: encryptedKey.Data, // Primary encrypted key for backward compatibility
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
		Recipients:   []*RecipientInfo{recipient}, // Single recipient info
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// EncryptWithCertificate encrypts data using a certificate's public key
func (e *EnvelopeEncryptor) EncryptWithCertificate(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	publicKey := certificate.Certificate.PublicKey
	return e.EncryptForPublicKey(data, publicKey, opts)
}

// EncryptForMultipleRecipients encrypts data for multiple recipients
func (e *EnvelopeEncryptor) EncryptForMultipleRecipients(data []byte, recipients []any, opts EncryptOptions) (*EncryptedData, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Generate random AES-256 key for data encryption
	aesKey, err := GenerateAESKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	symmetricOpts := EncryptOptions{
		Algorithm: AlgorithmAESGCM,
		Format:    opts.Format,
		Metadata:  make(map[string]interface{}),
	}

	encryptedData, err := e.symmetric.EncryptAESGCM(data, aesKey, symmetricOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with AES: %w", err)
	}

	// Encrypt AES key for each recipient
	var recipientInfos []*RecipientInfo
	for i, publicKey := range recipients {
		keyEncryptOpts := EncryptOptions{
			Algorithm: GetAlgorithmForKeyType(getPublicKeyType(publicKey)),
			Format:    FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		encryptedKey, err := e.asymmetric.EncryptForPublicKey(aesKey, publicKey, keyEncryptOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt AES key for recipient %d: %w", i, err)
		}

		recipientInfos = append(recipientInfos, &RecipientInfo{
			KeyID:                  []byte(fmt.Sprintf("recipient-%d", i)),
			EncryptedKey:           encryptedKey.Data,
			KeyEncryptionAlgorithm: encryptedKey.Algorithm,
			EphemeralKey:           encryptedKey.EncryptedKey, // For ECDSA/Ed25519
			KeyIV:                  encryptedKey.IV,
			KeyTag:                 encryptedKey.Tag,
		})
	}

	// Use first recipient's encrypted key as primary
	primaryEncryptedKey := recipientInfos[0].EncryptedKey

	return &EncryptedData{
		Algorithm:    AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: primaryEncryptedKey,
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
		Recipients:   recipientInfos,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// DecryptForRecipient decrypts multi-recipient envelope data for a specific recipient
func (e *EnvelopeEncryptor) DecryptForRecipient(encrypted *EncryptedData, keyPair any, recipientIndex int, opts DecryptOptions) ([]byte, error) {
	if encrypted.Algorithm != AlgorithmEnvelope {
		return nil, fmt.Errorf("expected envelope algorithm, got %s", encrypted.Algorithm)
	}

	if len(encrypted.Recipients) == 0 {
		// Fallback to single-recipient decryption
		return e.Decrypt(encrypted, keyPair, opts)
	}

	if recipientIndex < 0 || recipientIndex >= len(encrypted.Recipients) {
		return nil, fmt.Errorf("invalid recipient index: %d", recipientIndex)
	}

	recipient := encrypted.Recipients[recipientIndex]

	// Decrypt AES key using recipient's private key
	keyDecryptOpts := DecryptOptions{
		ExpectedAlgorithm: recipient.KeyEncryptionAlgorithm,
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: make(map[string]interface{}),
	}

	keyEncryptedData := &EncryptedData{
		Algorithm:    recipient.KeyEncryptionAlgorithm,
		Format:       FormatCMS,
		Data:         recipient.EncryptedKey,
		EncryptedKey: recipient.EphemeralKey, // For ECDSA/Ed25519 ephemeral keys
		IV:           recipient.KeyIV,
		Tag:          recipient.KeyTag,
	}

	aesKey, err := e.asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key for recipient %d: %w", recipientIndex, err)
	}

	// Decrypt data using recovered AES key
	dataEncryptedData := &EncryptedData{
		Algorithm: AlgorithmAESGCM,
		Format:    encrypted.Format,
		Data:      encrypted.Data,
		IV:        encrypted.IV,
		Tag:       encrypted.Tag,
	}

	dataDecryptOpts := DecryptOptions{
		ExpectedAlgorithm: AlgorithmAESGCM,
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: opts.ValidationOptions,
	}

	plaintext, err := e.symmetric.DecryptAESGCM(dataEncryptedData, aesKey, dataDecryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with AES: %w", err)
	}

	return plaintext, nil
}

// DecryptWithPrivateKey decrypts data using a private key (not supported for envelope encryption)
func (e *EnvelopeEncryptor) DecryptWithPrivateKey(encrypted *EncryptedData, privateKey any, opts DecryptOptions) ([]byte, error) {
	return nil, fmt.Errorf("DecryptWithPrivateKey not supported for envelope encryption - use Decrypt with key pair instead")
}

// SupportedAlgorithms returns the algorithms supported by the envelope encryptor
func (e *EnvelopeEncryptor) SupportedAlgorithms() []EncryptionAlgorithm {
	return []EncryptionAlgorithm{
		AlgorithmEnvelope,
		AlgorithmAESGCM,
		AlgorithmRSAOAEP,
		AlgorithmECDH,
		AlgorithmX25519,
	}
}

// Helper functions

func getKeyType(keyPair any) string {
	switch keyPair.(type) {
	case *algo.RSAKeyPair:
		return "RSA"
	case *algo.ECDSAKeyPair:
		return "ECDSA"
	case *algo.Ed25519KeyPair:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func getPublicKeyType(publicKey any) string {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// Type-safe wrapper functions using generic constraints

// EncryptEnvelope provides type-safe envelope encryption using generic constraints
func EncryptEnvelope[T keypair.KeyPair](data []byte, keyPair T, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewEnvelopeEncryptor()
	return encryptor.Encrypt(data, keyPair, opts)
}

// DecryptEnvelope provides type-safe envelope decryption using generic constraints
func DecryptEnvelope[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, opts DecryptOptions) ([]byte, error) {
	encryptor := NewEnvelopeEncryptor()
	return encryptor.Decrypt(encrypted, keyPair, opts)
}

// EncryptEnvelopeForPublicKey provides type-safe envelope encryption for public keys using generic constraints
func EncryptEnvelopeForPublicKey[T keypair.PublicKey](data []byte, publicKey T, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewEnvelopeEncryptor()
	return encryptor.EncryptForPublicKey(data, publicKey, opts)
}

// EncryptEnvelopeForMultipleRecipients provides type-safe multi-recipient envelope encryption using generic constraints
func EncryptEnvelopeForMultipleRecipients[T keypair.PublicKey](data []byte, recipients []T, opts EncryptOptions) (*EncryptedData, error) {
	// Convert to []any for the envelope encryptor
	anyRecipients := make([]any, len(recipients))
	for i, recipient := range recipients {
		anyRecipients[i] = recipient
	}
	encryptor := NewEnvelopeEncryptor()
	return encryptor.EncryptForMultipleRecipients(data, anyRecipients, opts)
}

// DecryptEnvelopeForRecipient provides type-safe multi-recipient envelope decryption using generic constraints
func DecryptEnvelopeForRecipient[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, recipientIndex int, opts DecryptOptions) ([]byte, error) {
	encryptor := NewEnvelopeEncryptor()
	return encryptor.DecryptForRecipient(encrypted, keyPair, recipientIndex, opts)
}

// EncryptEnvelopeWithCertificate provides type-safe certificate-based envelope encryption
func EncryptEnvelopeWithCertificate(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	encryptor := NewEnvelopeEncryptor()
	return encryptor.EncryptWithCertificate(data, certificate, opts)
}
