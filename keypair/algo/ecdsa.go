package algo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jasoet/gopki/keypair/format"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ECDSAKeyPair represents a generated ECDSA key pair containing both private and public keys.
// The public key is derived from the private key to ensure a mathematical relationship.
type ECDSAKeyPair struct {
	PrivateKey *ecdsa.PrivateKey // The ECDSA private key
	PublicKey  *ecdsa.PublicKey  // The corresponding ECDSA public key
}

// ECDSACurve represents the available elliptic curves for ECDSA key generation.
// Each curve offers different security levels and performance characteristics.
type ECDSACurve int

const (
	// P224 represents the NIST P-224 curve (112-bit security level)
	// Less commonly used, mainly for legacy compatibility
	P224 ECDSACurve = iota

	// P256 represents the NIST P-256 curve (128-bit security level)
	// Most widely used curve, good balance of security and performance
	P256

	// P384 represents the NIST P-384 curve (192-bit security level)
	// Higher security level, commonly used in enterprise environments
	P384

	// P521 represents the NIST P-521 curve (256-bit security level)
	// Highest security level, used for extremely sensitive applications
	P521
)

// Curve returns the corresponding elliptic.Curve for the ECDSACurve value.
// This method maps the enum values to the actual curve implementations.
//
// Returns:
//   - elliptic.Curve: The corresponding curve implementation
//   - Defaults to P256 for invalid curve values
//
// Example:
//
//	curve := P256.Curve() // Returns elliptic.P256()
func (c ECDSACurve) Curve() elliptic.Curve {
	switch c {
	case P224:
		return elliptic.P224()
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

// GenerateECDSAKeyPair generates a new ECDSA key pair using the specified elliptic curve.
// The function uses cryptographically secure random number generation.
//
// Parameters:
//   - curve: The elliptic curve to use (P224, P256, P384, or P521)
//
// Returns:
//   - *ECDSAKeyPair: The generated key pair
//   - error: Error if key generation fails
//
// Security considerations:
//   - Uses crypto/rand.Reader for secure random number generation
//   - P256 is recommended for most applications (good security/performance balance)
//   - P384 and P521 provide higher security levels at the cost of performance
//
// Example:
//
//	keyPair, err := GenerateECDSAKeyPair(P256)
//	if err != nil {
//		log.Printf("ECDSA key generation failed: %v", err)
//	}
func GenerateECDSAKeyPair(curve ECDSACurve) (*ECDSAKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve.Curve(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	return &ECDSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PrivateKeyToPEM converts the ECDSA private key to PEM format using PKCS#8 encoding.
// PKCS#8 format provides better interoperability compared to SEC 1 format.
//
// Returns:
//   - PEM: PEM-encoded private key data
//   - error: Error if marshaling or encoding fails
//
// The returned PEM block will have the type "PRIVATE KEY" and contain the
// PKCS#8 encoded private key data.
//
// Example:
//
//	pemData, err := keyPair.PrivateKeyToPEM()
//	if err != nil {
//		log.Printf("Private key PEM conversion failed: %v", err)
//	}
func (kp *ECDSAKeyPair) PrivateKeyToPEM() (format.PEM, error) {
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

// PublicKeyToPEM converts the ECDSA public key to PEM format using PKIX encoding.
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
func (kp *ECDSAKeyPair) PublicKeyToPEM() (format.PEM, error) {
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

// ECDSAKeyPairFromPEM reconstructs an ECDSA key pair from PEM-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyPEM: PEM-encoded private key data in PKCS#8 format
//
// Returns:
//   - *ECDSAKeyPair: The reconstructed key pair
//   - error: Error if PEM decoding, parsing, or type assertion fails
//
// The function expects the PEM block to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an ECDSA key before returning.
//
// Example:
//
//	keyPair, err := ECDSAKeyPairFromPEM(pemData)
//	if err != nil {
//		log.Printf("Failed to reconstruct ECDSA key pair: %v", err)
//	}
func ECDSAKeyPairFromPEM(privateKeyPEM format.PEM) (*ECDSAKeyPair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key")
	}

	return &ECDSAKeyPair{
		PrivateKey: ecdsaPrivateKey,
		PublicKey:  &ecdsaPrivateKey.PublicKey,
	}, nil
}

// PrivateKeyToDER converts the ECDSA private key to DER (Distinguished Encoding Rules) format.
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
func (kp *ECDSAKeyPair) PrivateKeyToDER() (format.DER, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to DER: %w", err)
	}
	return derBytes, nil
}

// PublicKeyToDER converts the ECDSA public key to DER (Distinguished Encoding Rules) format.
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
func (kp *ECDSAKeyPair) PublicKeyToDER() (format.DER, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	return derBytes, nil
}

// PublicKeyToSSH converts the ECDSA public key to SSH public key format.
// The SSH format is used in authorized_keys files and for key identification.
//
// Parameters:
//   - comment: Optional comment to include in the SSH key (commonly username@hostname)
//
// Returns:
//   - SSH: SSH public key in format "ecdsa-sha2-nistp256 base64-key [comment]"
//   - error: Error if conversion fails
//
// Example:
//
//	sshKey, err := keyPair.PublicKeyToSSH("user@example.com")
//	if err != nil {
//		log.Printf("SSH conversion failed: %v", err)
//	}
func (kp *ECDSAKeyPair) PublicKeyToSSH(comment string) (format.SSH, error) {
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

// PrivateKeyToSSH converts the ECDSA private key to OpenSSH private key format.
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
func (kp *ECDSAKeyPair) PrivateKeyToSSH(comment string, passphrase string) (format.SSH, error) {
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

// ECDSAKeyPairFromDER reconstructs an ECDSA key pair from DER-encoded private key data.
// The function parses the private key and derives the public key from it.
//
// Parameters:
//   - privateKeyDER: DER-encoded private key data in PKCS#8 format
//
// Returns:
//   - *ECDSAKeyPair: The reconstructed key pair
//   - error: Error if parsing or type assertion fails
//
// The function expects the DER data to contain a PKCS#8 encoded private key.
// It will validate that the key is actually an ECDSA key before returning.
//
// Example:
//
//	keyPair, err := ECDSAKeyPairFromDER(derData)
//	if err != nil {
//		log.Printf("Failed to reconstruct ECDSA key pair from DER: %v", err)
//	}
func ECDSAKeyPairFromDER(privateKeyDER format.DER) (*ECDSAKeyPair, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER private key: %w", err)
	}

	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key")
	}

	return &ECDSAKeyPair{
		PrivateKey: ecdsaPrivateKey,
		PublicKey:  &ecdsaPrivateKey.PublicKey,
	}, nil
}

// ECDSAKeyPairFromSSH reconstructs an ECDSA key pair from SSH-encoded private key data.
// The function parses the SSH private key and derives the public key from it.
//
// Parameters:
//   - privateKeySSH: SSH-encoded private key data in OpenSSH format
//   - passphrase: Passphrase for encrypted keys (empty string for unencrypted)
//
// Returns:
//   - *ECDSAKeyPair: The reconstructed key pair
//   - error: Error if parsing, decryption, or type assertion fails
//
// The function expects the SSH data to contain an OpenSSH formatted private key.
// It will validate that the key is actually an ECDSA key before returning.
//
// Example:
//
//	keyPair, err := ECDSAKeyPairFromSSH(sshData, "passphrase")
//	if err != nil {
//		log.Printf("Failed to reconstruct ECDSA key pair from SSH: %v", err)
//	}
func ECDSAKeyPairFromSSH(privateKeySSH format.SSH, passphrase string) (*ECDSAKeyPair, error) {
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

	ecdsaPrivateKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("SSH private key is not an ECDSA key, got %T", rawKey)
	}

	return &ECDSAKeyPair{
		PrivateKey: ecdsaPrivateKey,
		PublicKey:  &ecdsaPrivateKey.PublicKey,
	}, nil
}
