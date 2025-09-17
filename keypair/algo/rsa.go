// Package algo provides algorithm-specific implementations for cryptographic key pair generation.
// This file contains RSA key pair generation and management functionality with security best practices.
package algo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeySize represents a secure RSA key size with predefined safe values only.
// This type enforces compile-time safety by restricting key sizes to security-approved values.
// Developers cannot create custom KeySize values - only predefined constants are allowed.
type KeySize struct {
	bits int // unexported field - cannot be set directly by external code
}

// Predefined RSA key sizes with security and performance recommendations.
// These are the ONLY valid KeySize values that can be used for key generation.
var (
	KeySize2048 = KeySize{bits: 2048} // Minimum secure key size, good performance (recommended for most use cases)
	KeySize3072 = KeySize{bits: 3072} // Enhanced security level, moderate performance impact
	KeySize4096 = KeySize{bits: 4096} // Maximum security level, slower performance (recommended for long-term security)
)

// Bits returns the key size in bits for internal cryptographic operations.
func (ks KeySize) Bits() int {
	return ks.bits
}

// RSAKeyPair represents a generated RSA key pair containing both private and public keys.
// The public key is derived from the private key to ensure mathematical relationship.
type RSAKeyPair struct {
	PrivateKey *rsa.PrivateKey // The RSA private key
	PublicKey  *rsa.PublicKey  // The corresponding RSA public key
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified key size.
// The function enforces a minimum key size of 2048 bits for security compliance.
//
// Parameters:
//   - keySize: The desired key size in bits (minimum 2048)
//
// Returns:
//   - *RSAKeyPair: The generated key pair
//   - error: Error if key size is too small or generation fails
//
// Security considerations:
//   - Uses crypto/rand.Reader for secure random number generation
//   - Enforces minimum 2048-bit key size as per current security standards
//   - Keys below 2048 bits are considered cryptographically weak
//
// Example:
//
//	keyPair, err := GenerateRSAKeyPair(KeySize2048)
//	if err != nil {
//		log.Printf("RSA key generation failed: %v", err)
//	}
func GenerateRSAKeyPair(keySize KeySize) (*RSAKeyPair, error) {
	bits := keySize.Bits()
	if bits < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	return &RSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PrivateKeyToPEM converts the RSA private key to PEM format using PKCS#8 encoding.
// PKCS#8 format provides better interoperability compared to PKCS#1.
//
// Returns:
//   - PEM: PEM-encoded private key data
//   - error: Error if marshaling or encoding fails
//
// The returned PEM block will have type "PRIVATE KEY" and contain the
// PKCS#8 encoded private key data.
//
// Example:
//
//	pemData, err := keyPair.PrivateKeyToPEM()
//	if err != nil {
//		log.Printf("Private key PEM conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PrivateKeyToPEM() (PEM, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return PEM(privateKeyPEM), nil
}

// PublicKeyToPEM converts the RSA public key to PEM format using PKIX encoding.
// PKIX format is the standard format for public key encoding in X.509 certificates.
//
// Returns:
//   - PEM: PEM-encoded public key data
//   - error: Error if marshaling or encoding fails
//
// The returned PEM block will have type "PUBLIC KEY" and contain the
// PKIX encoded public key data.
//
// Example:
//
//	pemData, err := keyPair.PublicKeyToPEM()
//	if err != nil {
//		log.Printf("Public key PEM conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PublicKeyToPEM() (PEM, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return PEM(publicKeyPEM), nil
}

// RSAKeyPairFromPEM reconstructs an RSA key pair from PEM-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyPEM: PEM-encoded private key data in PKCS#8 format
//
// Returns:
//   - *RSAKeyPair: The reconstructed key pair
//   - error: Error if PEM decoding, parsing, or type assertion fails
//
// The function expects the PEM block to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an RSA key before returning.
//
// Example:
//
//	keyPair, err := RSAKeyPairFromPEM(pemData)
//	if err != nil {
//		log.Printf("Failed to reconstruct RSA key pair: %v", err)
//	}
func RSAKeyPairFromPEM(privateKeyPEM PEM) (*RSAKeyPair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return &RSAKeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  &rsaPrivateKey.PublicKey,
	}, nil
}

// PrivateKeyToDER converts the RSA private key to DER (Distinguished Encoding Rules) format.
// DER is a binary format that is more compact than PEM and faster to parse.
//
// Returns:
//   - DER: DER-encoded private key data
//   - error: Error if marshaling fails
//
// The function uses PKCS#8 encoding for maximum compatibility across different systems.
// DER format is typically 30% smaller than equivalent PEM format.
//
// Example:
//
//	derData, err := keyPair.PrivateKeyToDER()
//	if err != nil {
//		log.Printf("DER conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PrivateKeyToDER() (DER, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to DER: %w", err)
	}
	return DER(derBytes), nil
}

// PublicKeyToDER converts the RSA public key to DER (Distinguished Encoding Rules) format.
// DER is a binary format that provides compact storage and fast parsing.
//
// Returns:
//   - []byte: DER-encoded public key data
//   - error: Error if marshaling fails
//
// The function uses PKIX encoding for standard compatibility.
// DER format is the binary equivalent of PEM without Base64 encoding and headers.
//
// Example:
//
//	derData, err := keyPair.PublicKeyToDER()
//	if err != nil {
//		log.Printf("DER conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PublicKeyToDER() (DER, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	return DER(derBytes), nil
}

// PublicKeyToSSH converts the RSA public key to SSH public key format.
// The SSH format is used in authorized_keys files and for key identification.
//
// Parameters:
//   - comment: Optional comment to include in the SSH key (commonly username@hostname)
//
// Returns:
//   - SSH: SSH public key in format "ssh-rsa base64-key [comment]"
//   - error: Error if conversion fails
//
// Example:
//
//	sshKey, err := keyPair.PublicKeyToSSH("user@example.com")
//	if err != nil {
//		log.Printf("SSH conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PublicKeyToSSH(comment string) (SSH, error) {
	sshPubKey, err := ssh.NewPublicKey(kp.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert to SSH public key: %w", err)
	}

	sshData := ssh.MarshalAuthorizedKey(sshPubKey)
	sshStr := strings.TrimSpace(string(sshData))

	// Add comment if provided and not already present
	if comment != "" && !strings.Contains(sshStr, comment) {
		parts := strings.SplitN(sshStr, " ", 3)
		if len(parts) >= 2 {
			sshStr = parts[0] + " " + parts[1] + " " + comment
		}
	}

	return SSH(sshStr), nil
}

// PrivateKeyToSSH converts the RSA private key to OpenSSH private key format.
// This format is used by OpenSSH for storing private keys, with optional passphrase protection.
//
// Parameters:
//   - comment: Optional comment to embed in the key file
//   - passphrase: Optional passphrase for key encryption (empty string for unencrypted)
//
// Returns:
//   - SSH: OpenSSH private key in PEM-like format
//   - error: Error if conversion fails
//
// Security note: Using a passphrase is recommended for private key storage.
//
// Example:
//
//	sshKey, err := keyPair.PrivateKeyToSSH("my-key", "secure-passphrase")
//	if err != nil {
//		log.Printf("SSH conversion failed: %v", err)
//	}
func (kp *RSAKeyPair) PrivateKeyToSSH(comment string, passphrase string) (SSH, error) {
	var pemBlock *pem.Block
	var err error

	if passphrase == "" {
		pemBlock, err = ssh.MarshalPrivateKey(kp.PrivateKey, comment)
	} else {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(kp.PrivateKey, comment, []byte(passphrase))
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal SSH private key: %w", err)
	}

	sshPrivateKey := pem.EncodeToMemory(pemBlock)
	return SSH(sshPrivateKey), nil
}

// RSAKeyPairFromDER reconstructs an RSA key pair from DER-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyDER: DER-encoded private key data in PKCS#8 format
//
// Returns:
//   - *RSAKeyPair: The reconstructed key pair
//   - error: Error if parsing or type assertion fails
//
// The function expects the DER data to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an RSA key before returning.
//
// Example:
//
//	keyPair, err := RSAKeyPairFromDER(derData)
//	if err != nil {
//		log.Printf("Failed to reconstruct RSA key pair from DER: %v", err)
//	}
func RSAKeyPairFromDER(privateKeyDER DER) (*RSAKeyPair, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return &RSAKeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  &rsaPrivateKey.PublicKey,
	}, nil
}

// RSAKeyPairFromSSH reconstructs an RSA key pair from SSH-encoded private key data.
// The function parses the SSH private key and derives the public key from it.
//
// Parameters:
//   - privateKeySSH: SSH-encoded private key data in OpenSSH format
//   - passphrase: Passphrase for encrypted keys (empty string for unencrypted)
//
// Returns:
//   - *RSAKeyPair: The reconstructed key pair
//   - error: Error if parsing, decryption, or type assertion fails
//
// The function expects the SSH data to contain an OpenSSH formatted private key.
// It will validate that the key is actually an RSA key before returning.
//
// Example:
//
//	keyPair, err := RSAKeyPairFromSSH(sshData, "passphrase")
//	if err != nil {
//		log.Printf("Failed to reconstruct RSA key pair from SSH: %v", err)
//	}
func RSAKeyPairFromSSH(privateKeySSH SSH, passphrase string) (*RSAKeyPair, error) {
	var rawKey interface{}
	var err error

	if passphrase == "" {
		rawKey, err = ssh.ParseRawPrivateKey([]byte(privateKeySSH))
	} else {
		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(privateKeySSH), []byte(passphrase))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	rsaPrivateKey, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("SSH private key is not an RSA key, got %T", rawKey)
	}

	return &RSAKeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  &rsaPrivateKey.PublicKey,
	}, nil
}
