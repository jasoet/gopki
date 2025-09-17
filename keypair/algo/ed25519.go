package algo

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jasoet/gopki/keypair/format"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Ed25519Config represents the configuration for Ed25519 key generation.
// Ed25519 has no configurable parameters, so this is used as a placeholder for generic constraints.
type Ed25519Config string

// Ed25519KeyPair represents a generated Ed25519 key pair containing both private and public keys.
// Ed25519 keys are fixed-length and offer high security with excellent performance.
type Ed25519KeyPair struct {
	PrivateKey ed25519.PrivateKey // The Ed25519 private key (64 bytes)
	PublicKey  ed25519.PublicKey  // The corresponding Ed25519 public key (32 bytes)
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
// Ed25519 is a modern elliptic curve signature algorithm that provides:
//   - High security (equivalent to ~3072-bit RSA)
//   - Fast key generation, signing, and verification
//   - Small key sizes (32-byte public keys, 64-byte private keys)
//   - Immunity to timing attacks
//
// Returns:
//   - *Ed25519KeyPair: The generated key pair
//   - error: Error if key generation fails
//
// Security considerations:
//   - Uses crypto/rand.Reader for secure random number generation
//   - No configurable parameters - the algorithm is designed to be secure by default
//   - Recommended for new applications requiring digital signatures
//
// Example:
//
//	keyPair, err := GenerateEd25519KeyPair()
//	if err != nil {
//		log.Printf("Ed25519 key generation failed: %v", err)
//	}
func GenerateEd25519KeyPair() (*Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	return &Ed25519KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// PrivateKeyToPEM converts the Ed25519 private key to PEM format using PKCS#8 encoding.
// PKCS#8 format ensures compatibility with standard cryptographic tools and libraries.
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
func (kp *Ed25519KeyPair) PrivateKeyToPEM() (format.PEM, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// PublicKeyToPEM converts the Ed25519 public key to PEM format using PKIX encoding.
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
func (kp *Ed25519KeyPair) PublicKeyToPEM() (format.PEM, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

// Ed25519KeyPairFromPEM reconstructs an Ed25519 key pair from PEM-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyPEM: PEM-encoded private key data in PKCS#8 format
//
// Returns:
//   - *Ed25519KeyPair: The reconstructed key pair
//   - error: Error if PEM decoding, parsing, or type assertion fails
//
// The function expects the PEM block to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an Ed25519 key before returning.
// The public key is derived directly from the private key.
//
// Example:
//
//	keyPair, err := Ed25519KeyPairFromPEM(pemData)
//	if err != nil {
//		log.Printf("Failed to reconstruct Ed25519 key pair: %v", err)
//	}
func Ed25519KeyPairFromPEM(privateKeyPEM format.PEM) (*Ed25519KeyPair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an Ed25519 key")
	}

	publicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	return &Ed25519KeyPair{
		PrivateKey: ed25519PrivateKey,
		PublicKey:  publicKey,
	}, nil
}

// PrivateKeyToDER converts the Ed25519 private key to DER (Distinguished Encoding Rules) format.
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
func (kp *Ed25519KeyPair) PrivateKeyToDER() (format.DER, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to DER: %w", err)
	}
	return derBytes, nil
}

// PublicKeyToDER converts the Ed25519 public key to DER (Distinguished Encoding Rules) format.
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
func (kp *Ed25519KeyPair) PublicKeyToDER() (format.DER, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	return derBytes, nil
}

// PublicKeyToSSH converts the Ed25519 public key to SSH public key format.
// The SSH format is used in authorized_keys files and for key identification.
//
// Parameters:
//   - comment: Optional comment to include in the SSH key (commonly username@hostname)
//
// Returns:
//   - SSH: SSH public key in format "ssh-ed25519 base64-key [comment]"
//   - error: Error if conversion fails
//
// Example:
//
//	sshKey, err := keyPair.PublicKeyToSSH("user@example.com")
//	if err != nil {
//		log.Printf("SSH conversion failed: %v", err)
//	}
func (kp *Ed25519KeyPair) PublicKeyToSSH(comment string) (format.SSH, error) {
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

	return format.SSH(sshStr), nil
}

// PrivateKeyToSSH converts the Ed25519 private key to OpenSSH private key format.
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
func (kp *Ed25519KeyPair) PrivateKeyToSSH(comment string, passphrase string) (format.SSH, error) {
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
	return format.SSH(sshPrivateKey), nil
}

// Ed25519KeyPairFromDER reconstructs an Ed25519 key pair from DER-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyDER: DER-encoded private key data in PKCS#8 format
//
// Returns:
//   - *Ed25519KeyPair: The reconstructed key pair
//   - error: Error if parsing or type assertion fails
//
// The function expects the DER data to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an Ed25519 key before returning.
// The public key is derived directly from the private key.
//
// Example:
//
//	keyPair, err := Ed25519KeyPairFromDER(derData)
//	if err != nil {
//		log.Printf("Failed to reconstruct Ed25519 key pair from DER: %v", err)
//	}
func Ed25519KeyPairFromDER(privateKeyDER format.DER) (*Ed25519KeyPair, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER private key: %w", err)
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an Ed25519 key")
	}

	publicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	return &Ed25519KeyPair{
		PrivateKey: ed25519PrivateKey,
		PublicKey:  publicKey,
	}, nil
}

// Ed25519KeyPairFromSSH reconstructs an Ed25519 key pair from SSH-encoded private key data.
// The function parses the SSH private key and derives the public key from it.
//
// Parameters:
//   - privateKeySSH: SSH-encoded private key data in OpenSSH format
//   - passphrase: Passphrase for encrypted keys (empty string for unencrypted)
//
// Returns:
//   - *Ed25519KeyPair: The reconstructed key pair
//   - error: Error if parsing, decryption, or type assertion fails
//
// The function expects the SSH data to contain an OpenSSH formatted private key.
// It will validate that the key is actually an Ed25519 key before returning.
// The public key is derived directly from the private key.
//
// Example:
//
//	keyPair, err := Ed25519KeyPairFromSSH(sshData, "passphrase")
//	if err != nil {
//		log.Printf("Failed to reconstruct Ed25519 key pair from SSH: %v", err)
//	}
func Ed25519KeyPairFromSSH(privateKeySSH format.SSH, passphrase string) (*Ed25519KeyPair, error) {
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

	// Handle both *ed25519.PrivateKey and ed25519.PrivateKey types
	var ed25519PrivateKey ed25519.PrivateKey
	switch key := rawKey.(type) {
	case ed25519.PrivateKey:
		ed25519PrivateKey = key
	case *ed25519.PrivateKey:
		ed25519PrivateKey = *key
	default:
		return nil, fmt.Errorf("SSH private key is not an Ed25519 key, got %T", rawKey)
	}

	publicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	return &Ed25519KeyPair{
		PrivateKey: ed25519PrivateKey,
		PublicKey:  publicKey,
	}, nil
}
