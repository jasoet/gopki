package encryption

import (
	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// EncryptData is a high-level function that encrypts data using the most appropriate method
// based on the key pair type. It automatically selects between direct asymmetric encryption
// (for small data with RSA) or envelope encryption (for larger data or ECDSA/Ed25519 keys).
func EncryptData[T keypair.KeyPair](data []byte, keyPair T, opts EncryptOptions) (*EncryptedData, error) {
	// Use envelope encryption by default for consistency and efficiency
	envelope := NewEnvelopeEncryptor()
	return envelope.Encrypt(data, keyPair, opts)
}

// DecryptData is a high-level function that decrypts data using the appropriate method
// based on the encryption algorithm specified in the encrypted data.
func DecryptData[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, opts DecryptOptions) ([]byte, error) {
	switch encrypted.Algorithm {
	case AlgorithmRSAOAEP, AlgorithmECDH, AlgorithmX25519:
		// Direct asymmetric decryption
		asymmetric := NewAsymmetricEncryptor()
		return asymmetric.Decrypt(encrypted, keyPair, opts)

	case AlgorithmAESGCM:
		// Direct symmetric decryption (requires separate key management)
		return nil, ErrInvalidParameters // AES-GCM requires external key

	case AlgorithmEnvelope:
		// Envelope decryption (hybrid approach)
		envelope := NewEnvelopeEncryptor()
		return envelope.Decrypt(encrypted, keyPair, opts)

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// EncryptForPublicKey encrypts data for a specific public key using the most appropriate method
func EncryptForPublicKey[T keypair.PublicKey](data []byte, publicKey T, opts EncryptOptions) (*EncryptedData, error) {
	envelope := NewEnvelopeEncryptor()
	return envelope.EncryptForPublicKey(data, publicKey, opts)
}

// EncryptWithCertificate encrypts data using a certificate's public key
func EncryptWithCertificate(data []byte, certificate *cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	certEncryptor := NewCertificateEncryptor()
	return certEncryptor.EncryptDocument(data, certificate, opts)
}

// EncryptForMultipleRecipients encrypts data for multiple recipients (public keys)
func EncryptForMultipleRecipients[T keypair.PublicKey](data []byte, recipients []T, opts EncryptOptions) (*EncryptedData, error) {
	// Convert to []any for the envelope encryptor
	anyRecipients := make([]any, len(recipients))
	for i, recipient := range recipients {
		anyRecipients[i] = recipient
	}
	envelope := NewEnvelopeEncryptor()
	return envelope.EncryptForMultipleRecipients(data, anyRecipients, opts)
}

// EncryptForMultipleCertificates encrypts data for multiple certificate holders
func EncryptForMultipleCertificates(data []byte, certificates []*cert.Certificate, opts EncryptOptions) (*EncryptedData, error) {
	certEncryptor := NewCertificateEncryptor()
	return certEncryptor.EncryptForMultipleCertificates(data, certificates, opts)
}

// DecryptForRecipient decrypts multi-recipient data for a specific recipient index
func DecryptForRecipient[T keypair.KeyPair](encrypted *EncryptedData, keyPair T, recipientIndex int, opts DecryptOptions) ([]byte, error) {
	if encrypted.Algorithm != AlgorithmEnvelope {
		return nil, ErrUnsupportedAlgorithm
	}

	envelope := NewEnvelopeEncryptor()
	return envelope.DecryptForRecipient(encrypted, keyPair, recipientIndex, opts)
}

// FindRecipientByCertificate finds the recipient index for a specific certificate
func FindRecipientByCertificate(encrypted *EncryptedData, certificate *cert.Certificate) (int, error) {
	certEncryptor := NewCertificateEncryptor()
	return certEncryptor.FindRecipientByCertificate(encrypted, certificate)
}

// EncryptSymmetric encrypts data using AES-GCM with a provided key
func EncryptSymmetric(data []byte, key []byte, opts EncryptOptions) (*EncryptedData, error) {
	symmetric := NewSymmetricEncryptor()
	return symmetric.EncryptAESGCM(data, key, opts)
}

// DecryptSymmetric decrypts AES-GCM encrypted data with a provided key
func DecryptSymmetric(encrypted *EncryptedData, key []byte, opts DecryptOptions) ([]byte, error) {
	symmetric := NewSymmetricEncryptor()
	return symmetric.DecryptAESGCM(encrypted, key, opts)
}

// QuickEncrypt provides a simple API for encrypting data with default options
func QuickEncrypt[T keypair.KeyPair](data []byte, keyPair T) (*EncryptedData, error) {
	return EncryptData(data, keyPair, DefaultEncryptOptions())
}

// QuickDecrypt provides a simple API for decrypting data with default options
func QuickDecrypt[T keypair.KeyPair](encrypted *EncryptedData, keyPair T) ([]byte, error) {
	return DecryptData(encrypted, keyPair, DefaultDecryptOptions())
}

// QuickEncryptWithCertificate provides a simple API for certificate-based encryption
func QuickEncryptWithCertificate(data []byte, certificate *cert.Certificate) (*EncryptedData, error) {
	opts := DefaultEncryptOptions()
	opts.IncludeCertificate = true
	return EncryptWithCertificate(data, certificate, opts)
}

// GetSupportedAlgorithms returns all supported encryption algorithms
func GetSupportedAlgorithms() []EncryptionAlgorithm {
	return []EncryptionAlgorithm{
		AlgorithmRSAOAEP,
		AlgorithmECDH,
		AlgorithmX25519,
		AlgorithmAESGCM,
		AlgorithmEnvelope,
	}
}

// IsAlgorithmSupported checks if an algorithm is supported
func IsAlgorithmSupported(algorithm EncryptionAlgorithm) bool {
	supported := GetSupportedAlgorithms()
	for _, alg := range supported {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// GetRecommendedAlgorithm returns the recommended algorithm for a key type
func GetRecommendedAlgorithm[T keypair.KeyPair](keyPair T) EncryptionAlgorithm {
	// For most use cases, envelope encryption is recommended
	// as it provides the best balance of security, performance, and flexibility
	return AlgorithmEnvelope
}

// EstimateEncryptedSize estimates the size of encrypted data
func EstimateEncryptedSize(dataSize int, algorithm EncryptionAlgorithm) int {
	switch algorithm {
	case AlgorithmRSAOAEP:
		// RSA-OAEP adds padding, approximately key size in bytes
		return 256 // Assume 2048-bit RSA key (256 bytes)

	case AlgorithmECDH, AlgorithmX25519:
		// ECDH/X25519 with AES-GCM adds IV, tag, and ephemeral key
		return dataSize + 12 + 16 + 64 // IV + tag + ephemeral key estimate

	case AlgorithmAESGCM:
		// AES-GCM adds IV and authentication tag
		return dataSize + 12 + 16 // IV + tag

	case AlgorithmEnvelope:
		// Envelope encryption adds encrypted AES key + IV + tag
		return dataSize + 256 + 12 + 16 // encrypted key + IV + tag estimate

	default:
		return dataSize + 256 // Conservative estimate
	}
}

// ValidateKeyPairForEncryption validates that a key pair is suitable for encryption
func ValidateKeyPairForEncryption[T keypair.KeyPair](keyPair T) error {
	if keyPair == nil {
		return ErrInvalidKey
	}

	// Additional validation based on key type
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		if kp.PrivateKey.N.BitLen() < 2048 {
			return ErrInvalidKey
		}
	case *algo.ECDSAKeyPair:
		// ECDSA keys are generally suitable for encryption via ECDH
		if kp.PrivateKey == nil || kp.PublicKey == nil {
			return ErrInvalidKey
		}
	case *algo.Ed25519KeyPair:
		// Ed25519 keys are suitable for encryption via X25519
		if len(kp.PrivateKey) != 64 || len(kp.PublicKey) != 32 {
			return ErrInvalidKey
		}
	default:
		return ErrUnsupportedAlgorithm
	}

	return nil
}
