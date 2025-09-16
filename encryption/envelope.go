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

// EnvelopeEncryptor implements hybrid envelope encryption
// It encrypts data with a symmetric key (AES-GCM) and then encrypts the symmetric key
// with the recipient's public key. This approach combines the efficiency of symmetric
// encryption with the key distribution benefits of asymmetric encryption.
type EnvelopeEncryptor struct {
	asymmetric *AsymmetricEncryptor
	symmetric  *SymmetricEncryptor
}

// NewEnvelopeEncryptor creates a new envelope encryptor
func NewEnvelopeEncryptor() *EnvelopeEncryptor {
	return &EnvelopeEncryptor{
		asymmetric: NewAsymmetricEncryptor(),
		symmetric:  NewSymmetricEncryptor(),
	}
}

// Encrypt encrypts data using envelope encryption (hybrid approach)
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
		Format:    FormatRaw,
		Metadata:  make(map[string]interface{}),
	}

	encryptedKey, err := e.asymmetric.Encrypt(aesKey, keyPair, keyEncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Create envelope encrypted data
	envelope := &EncryptedData{
		Algorithm:    AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: encryptedKey.Data,
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}

	// Add recipient info if certificates are available
	if opts.IncludeCertificate {
		envelope.Recipients = []*RecipientInfo{
			{
				EncryptedKey:           encryptedKey.Data,
				KeyEncryptionAlgorithm: encryptedKey.Algorithm,
			},
		}
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

	// Create temporary encrypted data for key decryption
	keyEncryptedData := &EncryptedData{
		Algorithm: GetAlgorithmForKeyType(getKeyType(keyPair)),
		Format:    FormatRaw,
		Data:      encrypted.EncryptedKey,
	}

	aesKey, err := e.asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
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
		Format:    FormatRaw,
		Metadata:  make(map[string]interface{}),
	}

	encryptedKey, err := e.asymmetric.EncryptForPublicKey(aesKey, publicKey, keyEncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	return &EncryptedData{
		Algorithm:    AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: encryptedKey.Data,
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
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
			Format:    FormatRaw,
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
		Algorithm: recipient.KeyEncryptionAlgorithm,
		Format:    FormatRaw,
		Data:      recipient.EncryptedKey,
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
