// Package envelope implements hybrid envelope encryption for efficient encryption
// of large data sets using a combination of symmetric and asymmetric cryptography.
//
// Envelope encryption (also known as hybrid encryption) is a cryptographic technique
// that combines the speed of symmetric encryption with the key distribution benefits
// of asymmetric encryption. It's the recommended approach for encrypting large amounts
// of data or when you need to encrypt for multiple recipients.
//
// How envelope encryption works:
//  1. Generate a random symmetric encryption key (Data Encryption Key - DEK)
//  2. Encrypt the actual data with the DEK using AES-GCM
//  3. Encrypt the DEK with the recipient's public key (Key Encryption Key - KEK)
//  4. Return both the encrypted data and the encrypted DEK
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
package envelope

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/asymmetric"
	"github.com/jasoet/gopki/encryption/symmetric"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/smallstep/pkcs7"
)

// Encrypt encrypts data using envelope encryption (hybrid approach) for efficient
// handling of data of any size with any supported key type.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - data: The plaintext data to encrypt (any size supported)
//   - keyPair: The recipient's key pair (public key used for DEK encryption)
//   - opts: Encryption options (algorithm will be set to AlgorithmEnvelope)
//
// Returns:
//   - *encryption.EncryptedData: Encrypted data with envelope algorithm and combined payload
//   - error: Any error during DEK generation, data encryption, or key encryption
//
// Example:
//
//	// Works with any key type
//	rsaKeys, _ := algo.GenerateRSAKeyPair(2048)
//	largeFile := make([]byte, 10*1024*1024)  // 10MB file
//	encrypted, err := envelope.Encrypt(largeFile, rsaKeys, opts)
func Encrypt[T keypair.KeyPair](data []byte, keyPair T, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if err := encryption.ValidateEncryptOptions(opts); err != nil {
		return nil, err
	}

	// Generate random AES-256 key for data encryption
	aesKey, err := symmetric.GenerateAESKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	symmetricOpts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmAESGCM,
		Format:    opts.Format,
		Metadata:  make(map[string]interface{}),
	}

	encryptedData, err := symmetric.EncryptAESGCM(data, aesKey, symmetricOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with AES: %w", err)
	}

	// Encrypt AES key with recipient's public key
	keyEncryptOpts := encryption.EncryptOptions{
		Algorithm: GetAlgorithmForKeyType(getKeyType(any(keyPair))),
		Format:    encryption.FormatCMS,
		Metadata:  make(map[string]interface{}),
	}

	encryptedKey, err := asymmetric.Encrypt(aesKey, keyPair, keyEncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Create recipient info with complete encrypted key data
	recipient := &encryption.RecipientInfo{
		EncryptedKey:           encryptedKey.Data,
		KeyEncryptionAlgorithm: encryptedKey.Algorithm,
		EphemeralKey:           encryptedKey.EncryptedKey, // For ECDSA/Ed25519
		KeyIV:                  encryptedKey.IV,
		KeyTag:                 encryptedKey.Tag,
	}

	// Create envelope encrypted data
	envelope := &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: encryptedKey.Data, // Keep for backward compatibility
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
		Recipients:   []*encryption.RecipientInfo{recipient},
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}

	return envelope, nil
}

// Decrypt decrypts envelope-encrypted data.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - encrypted: The envelope-encrypted data to decrypt
//   - keyPair: The recipient's key pair (private key used for DEK decryption)
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted plaintext data
//   - error: Any error during key or data decryption
//
// Example:
//
//	plaintext, err := envelope.Decrypt(encrypted, rsaKeys, opts)
func Decrypt[T keypair.KeyPair](encrypted *encryption.EncryptedData, keyPair T, opts encryption.DecryptOptions) ([]byte, error) {
	if err := encryption.ValidateDecryptOptions(opts); err != nil {
		return nil, err
	}

	if encrypted.Algorithm != encryption.AlgorithmEnvelope {
		return nil, fmt.Errorf("expected envelope algorithm, got %s", encrypted.Algorithm)
	}

	// Check if this is OpenSSL-compatible format
	if encrypted.Metadata != nil {
		if isOpenSSL, ok := encrypted.Metadata["openssl_compatible"].(bool); ok && isOpenSSL {
			// Check if already decrypted by DecodeFromCMS
			if alreadyDecrypted, ok := encrypted.Metadata["already_decrypted"].(bool); ok && alreadyDecrypted {
				// Data is already plaintext from OpenSSL PKCS#7 EnvelopedData decryption
				return encrypted.Data, nil
			}

			// Not yet decrypted - need to decrypt the PKCS#7 EnvelopedData
			rsaKeyPair, ok := any(keyPair).(*algo.RSAKeyPair)
			if !ok {
				return nil, fmt.Errorf("OpenSSL compatible format requires RSA key pair, got %T", keyPair)
			}

			// Get certificate from recipient info
			if len(encrypted.Recipients) == 0 || encrypted.Recipients[0].Certificate == nil {
				return nil, fmt.Errorf("OpenSSL compatible format requires certificate in recipient info")
			}

			return decryptOpenSSLCompatible(encrypted.Data, encrypted.Recipients[0].Certificate, rsaKeyPair.PrivateKey)
		}
	}

	// Decrypt AES key using recipient's private key
	keyDecryptOpts := encryption.DecryptOptions{
		ExpectedAlgorithm: GetAlgorithmForKeyType(getKeyType(any(keyPair))),
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: make(map[string]interface{}),
	}

	var aesKey []byte
	var err error

	// Try to use recipient info if available (new format with ECDSA/Ed25519 support)
	if len(encrypted.Recipients) > 0 {
		recipient := encrypted.Recipients[0] // Use first recipient
		keyEncryptedData := &encryption.EncryptedData{
			Algorithm:    recipient.KeyEncryptionAlgorithm,
			Format:       encryption.FormatCMS,
			Data:         recipient.EncryptedKey,
			EncryptedKey: recipient.EphemeralKey, // Ephemeral key for ECDSA/Ed25519
			IV:           recipient.KeyIV,
			Tag:          recipient.KeyTag,
		}

		aesKey, err = asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
	} else {
		// Fallback to legacy format (RSA only)
		keyEncryptedData := &encryption.EncryptedData{
			Algorithm: GetAlgorithmForKeyType(getKeyType(any(keyPair))),
			Format:    encryption.FormatCMS,
			Data:      encrypted.EncryptedKey,
		}

		aesKey, err = asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// Decrypt data using recovered AES key
	dataEncryptedData := &encryption.EncryptedData{
		Algorithm: encryption.AlgorithmAESGCM,
		Format:    encrypted.Format,
		Data:      encrypted.Data,
		IV:        encrypted.IV,
		Tag:       encrypted.Tag,
	}

	dataDecryptOpts := encryption.DecryptOptions{
		ExpectedAlgorithm: encryption.AlgorithmAESGCM,
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: opts.ValidationOptions,
	}

	plaintext, err := symmetric.DecryptAESGCM(dataEncryptedData, aesKey, dataDecryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with AES: %w", err)
	}

	return plaintext, nil
}

// EncryptForPublicKey encrypts data for a specific public key using envelope encryption.
//
// Type parameter:
//   - T: Public key type constrained to keypair.PublicKey interface
//
// Parameters:
//   - data: The plaintext data to encrypt
//   - publicKey: The recipient's public key
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: Envelope-encrypted data
//   - error: Any error during encryption
//
// Example:
//
//	publicKey := rsaKeys.PublicKey()
//	encrypted, err := envelope.EncryptForPublicKey(data, publicKey, opts)
func EncryptForPublicKey[T keypair.PublicKey](data []byte, publicKey T, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	// Generate random AES-256 key for data encryption
	aesKey, err := symmetric.GenerateAESKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	symmetricOpts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmAESGCM,
		Format:    opts.Format,
		Metadata:  make(map[string]interface{}),
	}

	encryptedData, err := symmetric.EncryptAESGCM(data, aesKey, symmetricOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with AES: %w", err)
	}

	// Encrypt AES key with recipient's public key
	keyEncryptOpts := encryption.EncryptOptions{
		Algorithm: GetAlgorithmForKeyType(getPublicKeyType(any(publicKey))),
		Format:    encryption.FormatCMS,
		Metadata:  make(map[string]interface{}),
	}

	encryptedKey, err := asymmetric.EncryptForPublicKeyAny(aesKey, any(publicKey), keyEncryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Create recipient info
	recipient := &encryption.RecipientInfo{
		EncryptedKey:           encryptedKey.Data,
		KeyEncryptionAlgorithm: encryptedKey.Algorithm,
		EphemeralKey:           encryptedKey.EncryptedKey,
		KeyIV:                  encryptedKey.IV,
		KeyTag:                 encryptedKey.Tag,
	}

	return &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmEnvelope,
		Format:       opts.Format,
		Data:         encryptedData.Data,
		EncryptedKey: encryptedKey.Data,
		IV:           encryptedData.IV,
		Tag:          encryptedData.Tag,
		Recipients:   []*encryption.RecipientInfo{recipient},
		Timestamp:    time.Now(),
		Metadata:     opts.Metadata,
	}, nil
}

// EncryptForMultipleRecipients encrypts data for multiple recipients.
//
// Parameters:
//   - data: The data to encrypt
//   - recipients: List of recipient public keys
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: Multi-recipient encrypted data
//   - error: Any error during encryption
//
// Example:
//
//	recipients := []keypair.GenericPublicKey{aliceKey, bobKey, charlieKey}
//	encrypted, err := envelope.EncryptForMultipleRecipients(data, recipients, opts)
func EncryptForMultipleRecipients(data []byte, recipients []keypair.GenericPublicKey, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Generate random AES-256 key for data encryption
	aesKey, err := symmetric.GenerateAESKey(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	symmetricOpts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmAESGCM,
		Format:    opts.Format,
		Metadata:  make(map[string]interface{}),
	}

	encryptedData, err := symmetric.EncryptAESGCM(data, aesKey, symmetricOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with AES: %w", err)
	}

	// Encrypt AES key for each recipient
	var recipientInfos []*encryption.RecipientInfo
	for i, publicKey := range recipients {
		keyEncryptOpts := encryption.EncryptOptions{
			Algorithm: GetAlgorithmForKeyType(getPublicKeyType(publicKey)),
			Format:    encryption.FormatCMS,
			Metadata:  make(map[string]interface{}),
		}

		// Note: This will only work for RSA keys currently
		// ECDSA and Ed25519 would need ephemeral key generation
		encryptedKey, err := asymmetric.EncryptForPublicKeyAny(aesKey, any(publicKey), keyEncryptOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt AES key for recipient %d: %w", i, err)
		}

		recipientInfos = append(recipientInfos, &encryption.RecipientInfo{
			KeyID:                  []byte(fmt.Sprintf("recipient-%d", i)),
			EncryptedKey:           encryptedKey.Data,
			KeyEncryptionAlgorithm: encryptedKey.Algorithm,
			EphemeralKey:           encryptedKey.EncryptedKey,
			KeyIV:                  encryptedKey.IV,
			KeyTag:                 encryptedKey.Tag,
		})
	}

	// Use first recipient's encrypted key as primary
	primaryEncryptedKey := recipientInfos[0].EncryptedKey

	return &encryption.EncryptedData{
		Algorithm:    encryption.AlgorithmEnvelope,
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

// DecryptForRecipient decrypts multi-recipient envelope data for a specific recipient.
//
// Type parameter:
//   - T: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - encrypted: The multi-recipient encrypted data
//   - keyPair: The recipient's key pair
//   - recipientIndex: The index of this recipient in the recipient list
//   - opts: Decryption options
//
// Returns:
//   - []byte: The decrypted data
//   - error: Any error during decryption
//
// Example:
//
//	// Decrypt as recipient at index 1
//	plaintext, err := envelope.DecryptForRecipient(encrypted, bobKeys, 1, opts)
func DecryptForRecipient[T keypair.KeyPair](encrypted *encryption.EncryptedData, keyPair T, recipientIndex int, opts encryption.DecryptOptions) ([]byte, error) {
	if encrypted.Algorithm != encryption.AlgorithmEnvelope {
		return nil, fmt.Errorf("expected envelope algorithm, got %s", encrypted.Algorithm)
	}

	if len(encrypted.Recipients) == 0 {
		// Fallback to single-recipient decryption
		return Decrypt(encrypted, keyPair, opts)
	}

	if recipientIndex < 0 || recipientIndex >= len(encrypted.Recipients) {
		return nil, fmt.Errorf("invalid recipient index: %d", recipientIndex)
	}

	recipient := encrypted.Recipients[recipientIndex]

	// Decrypt AES key using recipient's private key
	keyDecryptOpts := encryption.DecryptOptions{
		ExpectedAlgorithm: recipient.KeyEncryptionAlgorithm,
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: make(map[string]interface{}),
	}

	keyEncryptedData := &encryption.EncryptedData{
		Algorithm:    recipient.KeyEncryptionAlgorithm,
		Format:       encryption.FormatCMS,
		Data:         recipient.EncryptedKey,
		EncryptedKey: recipient.EphemeralKey,
		IV:           recipient.KeyIV,
		Tag:          recipient.KeyTag,
	}

	aesKey, err := asymmetric.Decrypt(keyEncryptedData, keyPair, keyDecryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key for recipient %d: %w", recipientIndex, err)
	}

	// Decrypt data using recovered AES key
	dataEncryptedData := &encryption.EncryptedData{
		Algorithm: encryption.AlgorithmAESGCM,
		Format:    encrypted.Format,
		Data:      encrypted.Data,
		IV:        encrypted.IV,
		Tag:       encrypted.Tag,
	}

	dataDecryptOpts := encryption.DecryptOptions{
		ExpectedAlgorithm: encryption.AlgorithmAESGCM,
		VerifyTimestamp:   opts.VerifyTimestamp,
		MaxAge:            opts.MaxAge,
		ValidationOptions: opts.ValidationOptions,
	}

	plaintext, err := symmetric.DecryptAESGCM(dataEncryptedData, aesKey, dataDecryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with AES: %w", err)
	}

	return plaintext, nil
}

// encryptOpenSSLCompatible encrypts data using standard PKCS#7 EnvelopedData format
// compatible with OpenSSL. This only works with RSA keys.
func encryptOpenSSLCompatible(data []byte, certificates []*x509.Certificate) (*encryption.EncryptedData, error) {
	// Verify all certificates have RSA keys
	for i, cert := range certificates {
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("OpenSSL compatible mode requires RSA keys, certificate %d has %T", i, cert.PublicKey)
		}
	}

	// Set encryption algorithm to AES-256-GCM (standard for PKCS#7)
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM

	// Use PKCS#7 library to create standard EnvelopedData
	cmsData, err := pkcs7.Encrypt(data, certificates)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenSSL-compatible envelope: %w", err)
	}

	// Create recipient info for each certificate
	recipients := make([]*encryption.RecipientInfo, len(certificates))
	for i, cert := range certificates {
		recipients[i] = &encryption.RecipientInfo{
			Certificate:            cert,
			KeyEncryptionAlgorithm: encryption.AlgorithmRSAOAEP,
		}
	}

	// Return EncryptedData with the raw PKCS#7 data
	// Note: We store the entire CMS structure in Data field
	return &encryption.EncryptedData{
		Algorithm:  encryption.AlgorithmEnvelope,
		Format:     encryption.FormatCMS,
		Data:       cmsData, // Store complete PKCS#7 EnvelopedData
		Recipients: recipients,
		Timestamp:  time.Now(),
		Metadata:   map[string]any{"openssl_compatible": true},
	}, nil
}

// decryptOpenSSLCompatible decrypts OpenSSL-compatible PKCS#7 EnvelopedData
func decryptOpenSSLCompatible(cmsData []byte, cert *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Parse PKCS#7 structure
	p7, err := pkcs7.Parse(cmsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 envelope: %w", err)
	}

	// Decrypt using certificate and private key
	plaintext, err := p7.Decrypt(cert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PKCS#7 envelope: %w", err)
	}

	return plaintext, nil
}

// EncryptWithCertificate encrypts data using a certificate's public key.
//
// Parameters:
//   - data: The data to encrypt
//   - certificate: The recipient's certificate
//   - opts: Encryption options
//
// Returns:
//   - *encryption.EncryptedData: Envelope-encrypted data
//   - error: Any error during encryption
//
// Example:
//
//	encrypted, err := envelope.EncryptWithCertificate(data, recipientCert, opts)
func EncryptWithCertificate(data []byte, certificate *cert.Certificate, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	// Check if OpenSSL-compatible mode is requested
	if opts.OpenSSLCompatible {
		// Verify RSA key
		if _, ok := certificate.Certificate.PublicKey.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("OpenSSL compatible mode requires RSA certificate, got %T", certificate.Certificate.PublicKey)
		}

		// Use standard PKCS#7 EnvelopedData
		return encryptOpenSSLCompatible(data, []*x509.Certificate{certificate.Certificate})
	}

	// Use GoPKI's custom envelope encryption (supports all algorithms)
	publicKey := certificate.Certificate.PublicKey

	// Call the underlying encryption but then enhance with certificate info
	encryptedData, err := EncryptForPublicKeyAny(data, publicKey, opts)
	if err != nil {
		return nil, err
	}

	// Add certificate information to recipient info for CMS compatibility
	if len(encryptedData.Recipients) > 0 {
		encryptedData.Recipients[0].Certificate = certificate.Certificate
	}

	return encryptedData, nil
}

// EncryptForPublicKeyAny is a non-generic wrapper for EncryptForPublicKey that works with any public key type.
// This is used internally for dynamic dispatch when the public key type is not known at compile time.
func EncryptForPublicKeyAny(data []byte, publicKey keypair.GenericPublicKey, opts encryption.EncryptOptions) (*encryption.EncryptedData, error) {
	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		return EncryptForPublicKey(data, pk, opts)
	case *ecdsa.PublicKey:
		return EncryptForPublicKey(data, pk, opts)
	case ed25519.PublicKey:
		return asymmetric.EncryptForPublicKey(data, pk, opts)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// Helper functions

func getKeyType(keyPairAny keypair.GenericKeyPair) string {
	switch keyPairAny.(type) {
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

func getPublicKeyType(publicKeyAny keypair.GenericPublicKey) string {
	switch publicKeyAny.(type) {
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

// GetAlgorithmForKeyType returns the appropriate encryption algorithm for a key type
func GetAlgorithmForKeyType(keyType string) encryption.Algorithm {
	switch keyType {
	case "RSA":
		return encryption.AlgorithmRSAOAEP
	case "ECDSA":
		return encryption.AlgorithmECDH
	case "Ed25519":
		return encryption.AlgorithmX25519
	default:
		return encryption.AlgorithmEnvelope
	}
}
