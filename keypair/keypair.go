// Package keypair provides type-safe cryptographic key pair generation and management
// using Go generics for compile-time type safety. It supports RSA, ECDSA, and Ed25519
// algorithms with unified interfaces and format conversion utilities.
//
// The package uses generic constraints to ensure type safety at compile time:
//   - Param interface constrains key generation parameters
//   - KeyPair interface constrains key pair types
//   - PublicKey and PrivateKey interfaces constrain key types
//
// Example usage:
//
//	// Generate RSA key pair
//	rsaKeys, err := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//
//	// Generate ECDSA key pair
//	ecdsaKeys, err := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
//
//	// Generate Ed25519 key pair
//	ed25519Keys, err := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"

	"golang.org/x/crypto/ssh"
)

// Param defines the constraint for key generation parameters.
// It accepts KeySize for RSA, ECDSACurve for ECDSA, or Ed25519Config for Ed25519.
type Param interface {
	algo.KeySize | algo.ECDSACurve | algo.Ed25519Config
}

// KeyPair defines the constraint for key pair types.
// It accepts pointers to RSAKeyPair, ECDSAKeyPair, or Ed25519KeyPair.
type KeyPair interface {
	*algo.RSAKeyPair | *algo.ECDSAKeyPair | *algo.Ed25519KeyPair
}

// PublicKey defines the constraint for public key types.
// It accepts pointers to RSA/ECDSA public keys or Ed25519 public key values.
type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// PrivateKey defines the constraint for private key types.
// It accepts pointers to RSA/ECDSA private keys or Ed25519 private key values.
type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// GenericPrivateKey represents any private key type for functions that need to work with multiple key types dynamically
type GenericPrivateKey any

// GenericPublicKey represents any public key type for functions that need to work with multiple key types dynamically
type GenericPublicKey any

// GenericKeyPair represents any keypair type for functions that need to work with multiple keypair types dynamically
type GenericKeyPair any

// KeyPairManager provides type-safe operations for cryptographic key pairs.
// It encapsulates a key pair and provides methods for format conversion, validation,
// comparison, and file I/O operations while maintaining type safety through generics.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Example usage:
//
//	// Generate an RSA key pair manager
//	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
//
//	// Extract keys
//	privateKey := manager.PrivateKey()
//	publicKey := manager.PublicKey()
//
//	// Convert to formats
//	privatePEM, publicPEM, err := manager.ToPEM()
//
//	// Save to files
//	err = manager.SaveToPEM("private.pem", "public.pem")
type Manager[K KeyPair, P PrivateKey, B PublicKey] struct {
	keyPair    K
	privateKey P
	publicKey  B
}

// KeyInfo contains metadata about a cryptographic key pair.
// This information is useful for identifying key properties and ensuring
// compatibility with different cryptographic operations.
type KeyInfo struct {
	Algorithm string // "RSA", "ECDSA", "Ed25519"
	KeySize   int    // Bits for RSA, curve size for ECDSA, 256 for Ed25519
	Curve     string // For ECDSA: "P-256", "P-384", "P-521", etc. Empty for RSA and Ed25519
}

// NewManager creates a new KeyPairManager instance from an existing key pair.
// This constructor wraps an existing key pair to provide the manager's functionality.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - keyPair: The key pair to wrap in the manager
//
// Returns a new KeyPairManager instance.
//
// Example:
//
//	rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	manager := NewManager(rsaKeyPair)
func NewManager[K KeyPair, P PrivateKey, B PublicKey](keyPair K, privateKey P, publicKey B) *Manager[K, P, B] {
	return &Manager[K, P, B]{
		keyPair:    keyPair,
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// Generate creates a new KeyPairManager with a freshly generated key pair.
// This factory method generates a key pair using the specified parameters and wraps it in a manager.
//
// Type parameters:
//   - T: Parameter type (algo.KeySize, algo.ECDSACurve, or algo.Ed25519Config)
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - param: Algorithm-specific parameter (key size, curve, or config)
//
// Returns a new KeyPairManager instance or an error if generation fails.
//
// Examples:
//
//	// Generate RSA key pair manager
//	rsaManager, err := Generate[algo.KeySize, *algo.RSAKeyPair](algo.KeySize2048)
//
//	// Generate ECDSA key pair manager
//	ecdsaManager, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
//
//	// Generate Ed25519 key pair manager
//	ed25519Manager, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
func Generate[T Param, K KeyPair, P PrivateKey, B PublicKey](param T) (*Manager[K, P, B], error) {
	switch par := any(param).(type) {
	case algo.KeySize:
		kp, err := algo.GenerateRSAKeyPair(par)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
		return NewManager(any(kp).(K), any(kp.PrivateKey).(P), any(kp.PublicKey).(B)), nil
	case algo.ECDSACurve:
		kp, err := algo.GenerateECDSAKeyPair(par)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}
		return NewManager(any(kp).(K), any(kp.PrivateKey).(P), any(kp.PublicKey).(B)), nil
	case algo.Ed25519Config:
		kp, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
		}
		return NewManager(any(kp).(K), any(kp.PrivateKey).(P), any(kp.PublicKey).(B)), nil
	default:
		return nil, fmt.Errorf("unsupported parameter type")
	}
}

// KeyPair returns the underlying key pair managed by this instance.
//
// Returns the key pair of type K.
//
// Example:
//
//	keyPair := manager.KeyPair()
func (m *Manager[K, P, B]) KeyPair() K {
	return m.keyPair
}

// PrivateKey extracts the private key from the managed key pair.
// The returned type is determined by the key pair type and returned as interface{}.
// Use type assertion to convert to the specific key type you need.
//
// Returns the private key as interface{} or nil if extraction fails.
//
// Example:
//
//	privateKey := manager.PrivateKey()
//	if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
//		// Use RSA private key
//	}
func (m *Manager[K, P, B]) PrivateKey() P {
	return m.privateKey
}

// PublicKey extracts the public key from the managed key pair.
// The returned type is determined by the key pair type and returned as interface{}.
// Use type assertion to convert to the specific key type you need.
//
// Returns the public key as interface{} or nil if extraction fails.
//
// Example:
//
//	publicKey := manager.PublicKey()
//	if rsaKey, ok := publicKey.(*rsa.PublicKey); ok {
//		// Use RSA public key
//	}
func (m *Manager[K, P, B]) PublicKey() B {
	return m.publicKey
}

// ToPEM converts the managed key pair to PEM format, returning both private and public keys.
// This method provides a convenient way to get both keys in PEM format in a single call.
//
// Returns:
//   - privateKey: PEM-encoded private key in PKCS#8 format
//   - publicKey: PEM-encoded public key in PKIX format
//   - error: Error if conversion fails
//
// Example:
//
//	privatePEM, publicPEM, err := manager.ToPEM()
//	if err != nil {
//		log.Printf("Failed to convert to PEM: %v", err)
//	}
func (m *Manager[K, P, B]) ToPEM() (privateKey, publicKey format.PEM, err error) {
	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert RSA private key to PEM: %w", err)
		}
		publicKey, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert RSA public key to PEM: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKey, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert ECDSA private key to PEM: %w", err)
		}
		publicKey, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert ECDSA public key to PEM: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKey, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert Ed25519 private key to PEM: %w", err)
		}
		publicKey, err = PublicKeyToPEM(kp.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert Ed25519 public key to PEM: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key pair type")
	}

	return privateKey, publicKey, nil
}

// ToDER converts the managed key pair to DER format, returning both private and public keys.
// This method provides a convenient way to get both keys in DER format in a single call.
//
// Returns:
//   - privateKey: DER-encoded private key in PKCS#8 format
//   - publicKey: DER-encoded public key in PKIX format
//   - error: Error if conversion fails
//
// Example:
//
//	privateDER, publicDER, err := manager.ToDER()
//	if err != nil {
//		log.Printf("Failed to convert to DER: %v", err)
//	}
func (m *Manager[K, P, B]) ToDER() (privateKey, publicKey format.DER, err error) {
	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey, err = PrivateKeyToDER(kp.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert RSA private key to DER: %w", err)
		}
		publicKey, err = PublicKeyToDER(&kp.PrivateKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert RSA public key to DER: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKey, err = PrivateKeyToDER(kp.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert ECDSA private key to DER: %w", err)
		}
		publicKey, err = PublicKeyToDER(&kp.PrivateKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert ECDSA public key to DER: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKey, err = PrivateKeyToDER(kp.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert Ed25519 private key to DER: %w", err)
		}
		publicKey, err = PublicKeyToDER(kp.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert Ed25519 public key to DER: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key pair type")
	}

	return privateKey, publicKey, nil
}

// ToSSH converts the managed key pair to SSH format, returning both private and public keys.
// This method provides a convenient way to get both keys in SSH format in a single call.
//
// Parameters:
//   - comment: Optional comment to include in the SSH keys (commonly username@hostname)
//   - passphrase: Optional passphrase for private key encryption (empty string for unencrypted)
//
// Returns:
//   - privateKey: SSH-encoded private key in OpenSSH format
//   - publicKey: SSH-encoded public key in authorized_keys format
//   - error: Error if conversion fails
//
// Example:
//
//	privateSSH, publicSSH, err := manager.ToSSH("user@host", "passphrase")
//	if err != nil {
//		log.Printf("Failed to convert to SSH: %v", err)
//	}
func (m *Manager[K, P, B]) ToSSH(comment, passphrase string) (privateKey, publicKey format.SSH, err error) {
	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey, err = PrivateKeyToSSH(kp.PrivateKey, comment, passphrase)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert RSA private key to SSH: %w", err)
		}
		publicKey, err = PublicKeyToSSH(&kp.PrivateKey.PublicKey, comment)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert RSA public key to SSH: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKey, err = PrivateKeyToSSH(kp.PrivateKey, comment, passphrase)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert ECDSA private key to SSH: %w", err)
		}
		publicKey, err = PublicKeyToSSH(&kp.PrivateKey.PublicKey, comment)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert ECDSA public key to SSH: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKey, err = PrivateKeyToSSH(kp.PrivateKey, comment, passphrase)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert Ed25519 private key to SSH: %w", err)
		}
		publicKey, err = PublicKeyToSSH(kp.PublicKey, comment)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert Ed25519 public key to SSH: %w", err)
		}
	default:
		return "", "", fmt.Errorf("unsupported key pair type")
	}

	return privateKey, publicKey, nil
}

// LoadFromPEM creates a new KeyPairManager by loading a private key from a PEM file.
// The public key is automatically derived from the private key.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateKeyFile: Path to the PEM-encoded private key file
//
// Returns a new KeyPairManager instance or an error if loading fails.
//
// Example:
//
//	manager, err := LoadFromPEM[*algo.RSAKeyPair]("private.pem")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func LoadFromPEM[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string) (*Manager[K, P, B], error) {
	// Read private key file
	privateData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", privateKeyFile, err)
	}

	return LoadFromPEMData[K, P, B](privateData)
}

// LoadFromDER creates a new KeyPairManager by loading a private key from a DER file.
// The public key is automatically derived from the private key.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateKeyFile: Path to the DER-encoded private key file
//
// Returns a new KeyPairManager instance or an error if loading fails.
//
// Example:
//
//	manager, err := LoadFromDER[*algo.ECDSAKeyPair]("private.der")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func LoadFromDER[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string) (*Manager[K, P, B], error) {
	// Read private key file
	privateData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", privateKeyFile, err)
	}

	return LoadFromDERData[K, P, B](privateData)
}

// LoadFromSSH creates a new KeyPairManager by loading a private key from an SSH file.
// The public key is automatically derived from the private key.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateKeyFile: Path to the SSH-encoded private key file
//   - passphrase: Passphrase for encrypted private keys (empty string for unencrypted)
//
// Returns a new KeyPairManager instance or an error if loading fails.
//
// Example:
//
//	manager, err := LoadFromSSH[*algo.Ed25519KeyPair]("id_ed25519", "passphrase")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func LoadFromSSH[K KeyPair, P PrivateKey, B PublicKey](privateKeyFile string, passphrase string) (*Manager[K, P, B], error) {
	// Read private key file
	privateData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", privateKeyFile, err)
	}

	return LoadFromSSHData[K, P, B](format.SSH(privateData), passphrase)
}

// LoadFromPEMData creates a new KeyPairManager by parsing private key data in PEM format.
// The public key is automatically derived from the private key.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateKeyPEM: PEM-encoded private key data
//
// Returns a new KeyPairManager instance or an error if parsing fails.
//
// Example:
//
//	manager, err := LoadFromPEMData[*algo.RSAKeyPair](pemData)
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func LoadFromPEMData[K KeyPair, P PrivateKey, B PublicKey](privateKeyPEM format.PEM) (*Manager[K, P, B], error) {
	var zero K

	// Parse private key to determine type
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Reconstruct KeyPair based on private key type
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		keyPair := &algo.RSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(&priv.PublicKey).(B)), nil
		}
	case *ecdsa.PrivateKey:
		keyPair := &algo.ECDSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(&priv.PublicKey).(B)), nil
		}
	case ed25519.PrivateKey:
		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: priv,
			PublicKey:  priv.Public().(ed25519.PublicKey),
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(priv.Public().(ed25519.PublicKey)).(B)), nil
		}
	}

	return nil, fmt.Errorf("key type mismatch or unsupported key type: expected %T", zero)
}

// LoadFromDERData creates a new KeyPairManager by parsing private key data in DER format.
// The public key is automatically derived from the private key.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateKeyDER: DER-encoded private key data
//
// Returns a new KeyPairManager instance or an error if parsing fails.
//
// Example:
//
//	manager, err := LoadFromDERData[*algo.ECDSAKeyPair](derData)
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func LoadFromDERData[K KeyPair, P PrivateKey, B PublicKey](privateKeyDER format.DER) (*Manager[K, P, B], error) {
	var zero K

	// Parse private key to determine type
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Reconstruct KeyPair based on private key type
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		keyPair := &algo.RSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(&priv.PublicKey).(B)), nil
		}
	case *ecdsa.PrivateKey:
		keyPair := &algo.ECDSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(&priv.PublicKey).(B)), nil
		}
	case ed25519.PrivateKey:
		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: priv,
			PublicKey:  priv.Public().(ed25519.PublicKey),
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(priv.Public().(ed25519.PublicKey)).(B)), nil
		}
	}

	return nil, fmt.Errorf("key type mismatch or unsupported key type: expected %T", zero)
}

// LoadFromSSHData creates a new KeyPairManager by parsing private key data in SSH format.
// The public key is automatically derived from the private key.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateKeySSH: SSH-encoded private key data
//   - passphrase: Passphrase for encrypted private keys (empty string for unencrypted)
//
// Returns a new KeyPairManager instance or an error if parsing fails.
//
// Example:
//
//	manager, err := LoadFromSSHData[*algo.Ed25519KeyPair](sshData, "passphrase")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func LoadFromSSHData[K KeyPair, P PrivateKey, B PublicKey](privateKeySSH format.SSH, passphrase string) (*Manager[K, P, B], error) {
	var zero K
	var privateKey interface{}
	var err error

	// Parse private key to determine type
	if passphrase == "" {
		privateKey, err = ssh.ParseRawPrivateKey([]byte(privateKeySSH))
	} else {
		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(privateKeySSH), []byte(passphrase))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	// Reconstruct KeyPair based on private key type
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		keyPair := &algo.RSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(&priv.PublicKey).(B)), nil
		}
	case *ecdsa.PrivateKey:
		keyPair := &algo.ECDSAKeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(&priv.PublicKey).(B)), nil
		}
	case ed25519.PrivateKey:
		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: priv,
			PublicKey:  priv.Public().(ed25519.PublicKey),
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(priv).(P), any(priv.Public().(ed25519.PublicKey)).(B)), nil
		}
	case *ed25519.PrivateKey:
		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: *priv,
			PublicKey:  priv.Public().(ed25519.PublicKey),
		}
		if result, ok := any(keyPair).(K); ok {
			return NewManager(result, any(*priv).(P), any(priv.Public().(ed25519.PublicKey)).(B)), nil
		}
	}

	return nil, fmt.Errorf("key type mismatch or unsupported key type: expected %T", zero)
}

// GetInfo returns metadata about the managed key pair.
// This includes algorithm type, key size, and curve information for ECDSA keys.
//
// Returns KeyInfo struct with algorithm details or an error if analysis fails.
//
// Example:
//
//	info, err := manager.GetInfo()
//	if err != nil {
//		log.Printf("Failed to get key info: %v", err)
//	}
//	fmt.Printf("Algorithm: %s, KeySize: %d", info.Algorithm, info.KeySize)
func (m *Manager[K, P, B]) GetInfo() (KeyInfo, error) {
	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		return KeyInfo{
			Algorithm: "RSA",
			KeySize:   kp.PrivateKey.Size() * 8, // Convert bytes to bits
			Curve:     "",
		}, nil
	case *algo.ECDSAKeyPair:
		var curve string
		var keySize int

		switch kp.PrivateKey.Curve {
		case elliptic.P224():
			curve = "P-224"
			keySize = 224
		case elliptic.P256():
			curve = "P-256"
			keySize = 256
		case elliptic.P384():
			curve = "P-384"
			keySize = 384
		case elliptic.P521():
			curve = "P-521"
			keySize = 521
		default:
			curve = "Unknown"
			keySize = kp.PrivateKey.Curve.Params().BitSize
		}

		return KeyInfo{
			Algorithm: "ECDSA",
			KeySize:   keySize,
			Curve:     curve,
		}, nil
	case *algo.Ed25519KeyPair:
		return KeyInfo{
			Algorithm: "Ed25519",
			KeySize:   256, // Ed25519 keys are always 256 bits
			Curve:     "",
		}, nil
	default:
		return KeyInfo{}, fmt.Errorf("unsupported key pair type")
	}
}

// Validate verifies the mathematical relationship between the private and public keys.
// This ensures the key pair is valid and the public key correctly derives from the private key.
//
// Returns nil if the key pair is valid, or an error describing the validation failure.
//
// Example:
//
//	err := manager.Validate()
//	if err != nil {
//		log.Printf("Key pair validation failed: %v", err)
//	}
func (m *Manager[K, P, B]) Validate() error {
	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		// Verify RSA key pair relationship
		if kp.PrivateKey.PublicKey.N.Cmp(kp.PublicKey.N) != 0 {
			return fmt.Errorf("RSA public key N does not match private key")
		}
		if kp.PrivateKey.PublicKey.E != kp.PublicKey.E {
			return fmt.Errorf("RSA public key E does not match private key")
		}
		// Verify RSA private key components
		if err := kp.PrivateKey.Validate(); err != nil {
			return fmt.Errorf("RSA private key validation failed: %w", err)
		}
	case *algo.ECDSAKeyPair:
		// Verify ECDSA key pair relationship
		if kp.PrivateKey.PublicKey.X.Cmp(kp.PublicKey.X) != 0 {
			return fmt.Errorf("ECDSA public key X does not match private key")
		}
		if kp.PrivateKey.PublicKey.Y.Cmp(kp.PublicKey.Y) != 0 {
			return fmt.Errorf("ECDSA public key Y does not match private key")
		}
		if kp.PrivateKey.PublicKey.Curve != kp.PublicKey.Curve {
			return fmt.Errorf("ECDSA public key curve does not match private key")
		}
		// Verify the key is on the curve
		if !kp.PrivateKey.PublicKey.Curve.IsOnCurve(kp.PublicKey.X, kp.PublicKey.Y) {
			return fmt.Errorf("ECDSA public key is not on the specified curve")
		}
	case *algo.Ed25519KeyPair:
		// Verify Ed25519 key pair relationship
		derivedPublic := kp.PrivateKey.Public().(ed25519.PublicKey)
		if !derivedPublic.Equal(kp.PublicKey) {
			return fmt.Errorf("Ed25519 public key does not match private key")
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	return nil
}

// ValidatePrivateKey checks the validity and security standards of the private key.
// This includes verifying key size meets minimum security requirements.
//
// Returns nil if the private key is valid and secure, or an error describing the issue.
//
// Example:
//
//	err := manager.ValidatePrivateKey()
//	if err != nil {
//		log.Printf("Private key validation failed: %v", err)
//	}
func (m *Manager[K, P, B]) ValidatePrivateKey() error {
	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		// Check minimum key size (2048 bits)
		keySize := kp.PrivateKey.Size() * 8
		if keySize < 2048 {
			return fmt.Errorf("RSA key size %d bits is below minimum security requirement of 2048 bits", keySize)
		}
		// Validate RSA private key components
		if err := kp.PrivateKey.Validate(); err != nil {
			return fmt.Errorf("RSA private key validation failed: %w", err)
		}
	case *algo.ECDSAKeyPair:
		// Check that private key is not zero
		if kp.PrivateKey.D == nil || kp.PrivateKey.D.Sign() == 0 {
			return fmt.Errorf("ECDSA private key is zero or nil")
		}
		// Check that private key is within valid range for the curve
		n := kp.PrivateKey.Curve.Params().N
		if kp.PrivateKey.D.Cmp(n) >= 0 {
			return fmt.Errorf("ECDSA private key is outside valid range for curve")
		}
	case *algo.Ed25519KeyPair:
		// Ed25519 keys are always 64 bytes (512 bits) for private key
		if len(kp.PrivateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("Ed25519 private key has invalid size: expected %d bytes, got %d",
				ed25519.PrivateKeySize, len(kp.PrivateKey))
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	return nil
}

// CompareWith compares two key managers for mathematical equality.
// This method compares both the private and public keys to determine if they are identical.
//
// Parameters:
//   - other: Another KeyPairManager to compare with
//
// Returns:
//   - bool: true if both key pairs are mathematically identical, false otherwise
//
// Example:
//
//	isEqual := manager1.CompareWith(manager2)
//	if isEqual {
//		fmt.Println("Key pairs are identical")
//	}
func (m *Manager[K, P, B]) CompareWith(other *Manager[K, P, B]) bool {
	return m.ComparePrivateKeys(other) && m.ComparePublicKeys(other)
}

// ComparePrivateKeys compares only the private keys of two key managers.
// This method determines if the private keys are mathematically identical.
//
// Parameters:
//   - other: Another KeyPairManager to compare private keys with
//
// Returns:
//   - bool: true if private keys are identical, false otherwise
//
// Example:
//
//	arePrivateKeysEqual := manager1.ComparePrivateKeys(manager2)
func (m *Manager[K, P, B]) ComparePrivateKeys(other *Manager[K, P, B]) bool {
	switch kp1 := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		if kp2, ok := any(other.keyPair).(*algo.RSAKeyPair); ok {
			return kp1.PrivateKey.Equal(kp2.PrivateKey)
		}
	case *algo.ECDSAKeyPair:
		if kp2, ok := any(other.keyPair).(*algo.ECDSAKeyPair); ok {
			return kp1.PrivateKey.Equal(kp2.PrivateKey)
		}
	case *algo.Ed25519KeyPair:
		if kp2, ok := any(other.keyPair).(*algo.Ed25519KeyPair); ok {
			return kp1.PrivateKey.Equal(kp2.PrivateKey)
		}
	}
	return false
}

// ComparePublicKeys compares only the public keys of two key managers.
// This method determines if the public keys are mathematically identical.
//
// Parameters:
//   - other: Another KeyPairManager to compare public keys with
//
// Returns:
//   - bool: true if public keys are identical, false otherwise
//
// Example:
//
//	arePublicKeysEqual := manager1.ComparePublicKeys(manager2)
func (m *Manager[K, P, B]) ComparePublicKeys(other *Manager[K, P, B]) bool {
	switch kp1 := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		if kp2, ok := any(other.keyPair).(*algo.RSAKeyPair); ok {
			return kp1.PublicKey.Equal(kp2.PublicKey)
		}
	case *algo.ECDSAKeyPair:
		if kp2, ok := any(other.keyPair).(*algo.ECDSAKeyPair); ok {
			return kp1.PublicKey.Equal(kp2.PublicKey)
		}
	case *algo.Ed25519KeyPair:
		if kp2, ok := any(other.keyPair).(*algo.Ed25519KeyPair); ok {
			return kp1.PublicKey.Equal(kp2.PublicKey)
		}
	}
	return false
}

// Clone creates a new KeyPairManager with the same key pair.
// This method creates a shallow copy of the KeyPairManager, sharing the same underlying key pair data.
//
// Returns:
//   - *KeyPairManager[K]: A new KeyPairManager instance with the same key pair
//
// Note: This creates a shallow copy. The underlying cryptographic keys are shared between instances.
// If you need a deep copy with new cryptographic material, generate a new key pair instead.
//
// Example:
//
//	clonedManager := manager.Clone()
//	// clonedManager and manager share the same key pair data
func (m *Manager[K, P, B]) Clone() *Manager[K, P, B] {
	return &Manager[K, P, B]{
		keyPair: m.keyPair,
	}
}

// IsValid checks if the KeyPairManager is properly initialized.
// This method verifies that the KeyPairManager contains a valid key pair.
//
// Returns:
//   - bool: true if the manager is initialized with a valid key pair, false otherwise
//
// This method checks:
//   - KeyPairManager is not nil
//   - Key pair is not nil
//   - Key pair contains valid private and public keys
//
// Example:
//
//	if manager.IsValid() {
//		fmt.Println("Manager is ready to use")
//	} else {
//		fmt.Println("Manager is not properly initialized")
//	}
func (m *Manager[K, P, B]) IsValid() bool {
	if m == nil {
		return false
	}

	switch kp := any(m.keyPair).(type) {
	case *algo.RSAKeyPair:
		return kp != nil && kp.PrivateKey != nil && kp.PublicKey != nil
	case *algo.ECDSAKeyPair:
		return kp != nil && kp.PrivateKey != nil && kp.PublicKey != nil
	case *algo.Ed25519KeyPair:
		return kp != nil && len(kp.PrivateKey) == ed25519.PrivateKeySize && len(kp.PublicKey) == ed25519.PublicKeySize
	default:
		return false
	}
}

// SaveToPEM saves the managed key pair to separate PEM files.
// This method provides a convenient way to save both keys to files in PEM format.
//
// Parameters:
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := manager.SaveToPEM("private.pem", "public.pem")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func (m *Manager[K, P, B]) SaveToPEM(privateFile, publicFile string) error {
	privateKeyPEM, publicKeyPEM, err := m.ToPEM()
	if err != nil {
		return fmt.Errorf("failed to convert keys to PEM: %w", err)
	}

	if err := savePEMToFile(privateKeyPEM, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := savePEMToFile(publicKeyPEM, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// SaveToDER saves the managed key pair to separate DER files.
// This method provides a convenient way to save both keys to files in DER format.
//
// Parameters:
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := manager.SaveToDER("private.der", "public.der")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func (m *Manager[K, P, B]) SaveToDER(privateFile, publicFile string) error {
	privateKeyDER, publicKeyDER, err := m.ToDER()
	if err != nil {
		return fmt.Errorf("failed to convert keys to DER: %w", err)
	}

	if err := saveDERToFile(privateKeyDER, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := saveDERToFile(publicKeyDER, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// SaveToSSH saves the managed key pair to separate SSH files.
// This method provides a convenient way to save both keys to files in SSH format.
//
// Parameters:
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//   - comment: Optional comment to include in the SSH keys (commonly username@hostname)
//   - passphrase: Optional passphrase for private key encryption (empty string for unencrypted)
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := manager.SaveToSSH("id_rsa", "id_rsa.pub", "user@host", "passphrase")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func (m *Manager[K, P, B]) SaveToSSH(privateFile, publicFile string, comment, passphrase string) error {
	privateKeySSH, publicKeySSH, err := m.ToSSH(comment, passphrase)
	if err != nil {
		return fmt.Errorf("failed to convert keys to SSH: %w", err)
	}

	if err := saveSSHToFile(privateKeySSH, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := saveSSHToFile(publicKeySSH, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// PrivateKeyToPEM converts a private key to PEM-encoded format.
// The key is marshaled using PKCS#8 format for maximum compatibility.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//
// Returns PEM-encoded data or an error if conversion fails.
//
// Example:
//
//	pemData, err := PrivateKeyToPEM(rsaPrivateKey)
//	if err != nil {
//		log.Printf("Failed to convert private key: %v", err)
//	}
func PrivateKeyToPEM[T PrivateKey](privateKey T) (format.PEM, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// PublicKeyToPEM converts a public key to PEM-encoded format.
// The key is marshaled using PKIX format for standard compatibility.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//
// Returns PEM-encoded data or an error if conversion fails.
//
// Example:
//
//	pemData, err := PublicKeyToPEM(rsaPublicKey)
//	if err != nil {
//		log.Printf("Failed to convert public key: %v", err)
//	}
func PublicKeyToPEM[T PublicKey](publicKey T) (format.PEM, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

// PrivateKeyToDER converts a private key to DER-encoded format.
// The key is marshaled using PKCS#8 format for maximum compatibility.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//
// Returns DER-encoded data or an error if conversion fails.
//
// Example:
//
//	derData, err := PrivateKeyToDER(rsaPrivateKey)
//	if err != nil {
//		log.Printf("Failed to convert private key: %v", err)
//	}
func PrivateKeyToDER[T PrivateKey](privateKey T) (format.DER, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return privateKeyBytes, nil
}

// PublicKeyToDER converts a public key to DER-encoded format.
// The key is marshaled using PKIX format for standard compatibility.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//
// Returns DER-encoded data or an error if conversion fails.
//
// Example:
//
//	derData, err := PublicKeyToDER(rsaPublicKey)
//	if err != nil {
//		log.Printf("Failed to convert public key: %v", err)
//	}
func PublicKeyToDER[T PublicKey](publicKey T) (format.DER, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return publicKeyBytes, nil
}

// PrivateKeyToSSH converts a private key to SSH-encoded format.
// The key is marshaled using OpenSSH private key format with optional passphrase protection.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//   - comment: Optional comment to embed in the key file
//   - passphrase: Optional passphrase for key encryption (empty string for unencrypted)
//
// Returns SSH-encoded data or an error if conversion fails.
//
// Security note: Using a passphrase is recommended for private key storage.
//
// Example:
//
//	sshData, err := PrivateKeyToSSH(rsaPrivateKey, "my-key", "secure-passphrase")
//	if err != nil {
//		log.Printf("Failed to convert private key: %v", err)
//	}
func PrivateKeyToSSH[T PrivateKey](privateKey T, comment string, passphrase string) (format.SSH, error) {
	var pemBlock *pem.Block
	var err error

	if passphrase == "" {
		pemBlock, err = ssh.MarshalPrivateKey(privateKey, comment)
	} else {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, []byte(passphrase))
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal SSH private key: %w", err)
	}

	sshPrivateKey := pem.EncodeToMemory(pemBlock)
	return format.SSH(sshPrivateKey), nil
}

// PublicKeyToSSH converts a public key to SSH-encoded format.
// The key is marshaled using SSH public key format suitable for authorized_keys files.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//   - comment: Optional comment to include in the SSH key (commonly username@hostname)
//
// Returns SSH-encoded data in format "ssh-rsa base64-key [comment]" or an error if conversion fails.
//
// Example:
//
//	sshData, err := PublicKeyToSSH(rsaPublicKey, "user@example.com")
//	if err != nil {
//		log.Printf("Failed to convert public key: %v", err)
//	}
func PublicKeyToSSH[T PublicKey](publicKey T, comment string) (format.SSH, error) {
	sshPubKey, err := ssh.NewPublicKey(publicKey)
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

// PrivateKeyFromSSH parses a private key from SSH-encoded data.
// The function handles OpenSSH format with optional passphrase decryption.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - sshData: SSH-encoded private key data
//   - passphrase: Passphrase for encrypted keys (empty string for unencrypted)
//
// Returns the parsed private key or an error if parsing fails or type assertion fails.
//
// Example:
//
//	ed25519PrivKey, err := PrivateKeyFromSSH[ed25519.PrivateKey](sshData, "passphrase")
//	if err != nil {
//		log.Printf("Failed to parse private key: %v", err)
//	}
func PrivateKeyFromSSH[T PrivateKey](sshData format.SSH, passphrase string) (T, error) {
	var zero T
	var privateKey interface{}
	var err error

	if passphrase == "" {
		privateKey, err = ssh.ParseRawPrivateKey([]byte(sshData))
	} else {
		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshData), []byte(passphrase))
	}

	if err != nil {
		return zero, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	if typedKey, ok := privateKey.(T); ok {
		return typedKey, nil
	}

	return zero, fmt.Errorf("private key type mismatch: expected %T, got %T", zero, privateKey)
}

// PublicKeyFromPEM parses a public key from PEM-encoded data.
// The function expects PKIX format and returns the appropriate public key type.
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - pemData: PEM-encoded public key data
//
// Returns the parsed public key or an error if parsing fails or type assertion fails.
//
// Example:
//
//	rsaPubKey, err := PublicKeyFromPEM[*rsa.PublicKey](pemData)
//	if err != nil {
//		log.Printf("Failed to parse public key: %v", err)
//	}
func PublicKeyFromPEM[T PublicKey](pemData format.PEM) (T, error) {
	var zero T

	block, _ := pem.Decode(pemData)
	if block == nil {
		return zero, fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	if typedKey, ok := publicKey.(T); ok {
		return typedKey, nil
	}

	return zero, fmt.Errorf("public key type mismatch: expected %T, got %T", zero, publicKey)
}

// PublicKeyFromDER parses a public key from DER-encoded data.
// The function expects PKIX format and returns the appropriate public key type.
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - derData: DER-encoded public key data
//
// Returns the parsed public key or an error if parsing fails or type assertion fails.
//
// Example:
//
//	ecdsaPubKey, err := PublicKeyFromDER[*ecdsa.PublicKey](derData)
//	if err != nil {
//		log.Printf("Failed to parse public key: %v", err)
//	}
func PublicKeyFromDER[T PublicKey](derData format.DER) (T, error) {
	var zero T

	publicKey, err := x509.ParsePKIXPublicKey(derData)
	if err != nil {
		return zero, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	if typedKey, ok := publicKey.(T); ok {
		return typedKey, nil
	}

	return zero, fmt.Errorf("public key type mismatch: expected %T, got %T", zero, publicKey)
}

// PublicKeyFromSSH parses a public key from SSH-encoded data.
// The function handles SSH public key format (authorized_keys format).
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - sshData: SSH-encoded public key data
//
// Returns the parsed public key or an error if parsing fails or type assertion fails.
//
// Example:
//
//	ed25519PubKey, err := PublicKeyFromSSH[ed25519.PublicKey](sshData)
//	if err != nil {
//		log.Printf("Failed to parse public key: %v", err)
//	}
func PublicKeyFromSSH[T PublicKey](sshData format.SSH) (T, error) {
	var zero T

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshData))
	if err != nil {
		return zero, fmt.Errorf("failed to parse SSH public key: %w", err)
	}

	// Extract the underlying crypto.PublicKey
	var cryptoPublicKey interface{}

	// Check if it's a certificate first
	if cert, ok := publicKey.(*ssh.Certificate); ok {
		if cryptoKey, ok := cert.Key.(ssh.CryptoPublicKey); ok {
			cryptoPublicKey = cryptoKey.CryptoPublicKey()
		}
	} else if cryptoKey, ok := publicKey.(ssh.CryptoPublicKey); ok {
		// Regular SSH public key (not certificate)
		cryptoPublicKey = cryptoKey.CryptoPublicKey()
	} else {
		return zero, fmt.Errorf("cannot extract crypto public key from SSH key type: %s", publicKey.Type())
	}

	if typedKey, ok := cryptoPublicKey.(T); ok {
		return typedKey, nil
	}

	return zero, fmt.Errorf("public key type mismatch: expected %T, got %T", zero, cryptoPublicKey)
}

// GetPublicKey extracts the public key from a private key with type safety.
// This function works with all supported key types and maintains type relationships.
//
// Type parameters:
//   - TPriv: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//   - TPub: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - privateKey: The private key from which to extract the public key
//
// Returns the corresponding public key or an error if extraction fails.
//
// Example:
//
//	rsaPublicKey, err := GetPublicKey[*rsa.PrivateKey, *rsa.PublicKey](rsaPrivateKey)
//	if err != nil {
//		log.Printf("Failed to get public key: %v", err)
//	}
func GetPublicKey[TPriv PrivateKey, TPub PublicKey](privateKey TPriv) (TPub, error) {
	var zero TPub

	switch priv := any(privateKey).(type) {
	case *rsa.PrivateKey:
		if pub, ok := any(&priv.PublicKey).(TPub); ok {
			return pub, nil
		}
	case *ecdsa.PrivateKey:
		if pub, ok := any(&priv.PublicKey).(TPub); ok {
			return pub, nil
		}
	case ed25519.PrivateKey:
		if pub, ok := any(priv.Public().(ed25519.PublicKey)).(TPub); ok {
			return pub, nil
		}
	}

	return zero, fmt.Errorf("unsupported key type or type mismatch")
}

// ToPEMFiles saves a key pair to separate private and public key files in PEM format.
// The function creates the necessary directory structure and sets appropriate file permissions.
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - keyPair: The key pair to save
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency, though public keys could be more permissive)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := ToPEMFiles(rsaKeyPair, "private.pem", "public.pem")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func ToPEMFiles[T KeyPair](keyPair T, privateFile, publicFile string) error {
	var privateKeyPEM, publicKeyPEM format.PEM
	var err error

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA public key to PEM: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA public key to PEM: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKeyPEM, err = PrivateKeyToPEM(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 private key to PEM: %w", err)
		}
		publicKeyPEM, err = PublicKeyToPEM(kp.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 public key to PEM: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	if err := savePEMToFile(privateKeyPEM, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := savePEMToFile(publicKeyPEM, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// ToDERFiles saves a key pair to separate private and public key files in DER format.
// The function creates the necessary directory structure and sets appropriate file permissions.
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - keyPair: The key pair to save
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency, though public keys could be more permissive)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := ToDERFiles(rsaKeyPair, "private.der", "public.der")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func ToDERFiles[T KeyPair](keyPair T, privateFile, publicFile string) error {
	var privateKeyDER, publicKeyDER format.DER
	var err error

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKeyDER, err = PrivateKeyToDER(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA private key to DER: %w", err)
		}
		publicKeyDER, err = PublicKeyToDER(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert RSA public key to DER: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKeyDER, err = PrivateKeyToDER(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA private key to DER: %w", err)
		}
		publicKeyDER, err = PublicKeyToDER(&kp.PrivateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA public key to DER: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKeyDER, err = PrivateKeyToDER(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 private key to DER: %w", err)
		}
		publicKeyDER, err = PublicKeyToDER(kp.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 public key to DER: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	if err := saveDERToFile(privateKeyDER, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := saveDERToFile(publicKeyDER, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// ToSSHFiles saves a key pair to separate private and public key files in SSH format.
// The function creates the necessary directory structure and sets appropriate file permissions.
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - keyPair: The key pair to save
//   - privateFile: Path where the private key will be saved
//   - publicFile: Path where the public key will be saved
//   - comment: Optional comment to include in the SSH keys
//   - passphrase: Optional passphrase for private key encryption (empty string for unencrypted)
//
// File permissions:
//   - Private key files: 0600 (readable/writable by owner only)
//   - Public key files: 0600 (for consistency, though public keys could be more permissive)
//   - Directories: 0700 (accessible by owner only)
//
// Example:
//
//	err := ToSSHFiles(rsaKeyPair, "id_rsa", "id_rsa.pub", "user@host", "passphrase")
//	if err != nil {
//		log.Printf("Failed to save key pair: %v", err)
//	}
func ToSSHFiles[T KeyPair](keyPair T, privateFile, publicFile string, comment string, passphrase string) error {
	var privateKeySSH, publicKeySSH format.SSH
	var err error

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKeySSH, err = PrivateKeyToSSH(kp.PrivateKey, comment, passphrase)
		if err != nil {
			return fmt.Errorf("failed to convert RSA private key to SSH: %w", err)
		}
		publicKeySSH, err = PublicKeyToSSH(&kp.PrivateKey.PublicKey, comment)
		if err != nil {
			return fmt.Errorf("failed to convert RSA public key to SSH: %w", err)
		}
	case *algo.ECDSAKeyPair:
		privateKeySSH, err = PrivateKeyToSSH(kp.PrivateKey, comment, passphrase)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA private key to SSH: %w", err)
		}
		publicKeySSH, err = PublicKeyToSSH(&kp.PrivateKey.PublicKey, comment)
		if err != nil {
			return fmt.Errorf("failed to convert ECDSA public key to SSH: %w", err)
		}
	case *algo.Ed25519KeyPair:
		privateKeySSH, err = PrivateKeyToSSH(kp.PrivateKey, comment, passphrase)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 private key to SSH: %w", err)
		}
		publicKeySSH, err = PublicKeyToSSH(kp.PublicKey, comment)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 public key to SSH: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key pair type")
	}

	if err := saveSSHToFile(privateKeySSH, privateFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := saveSSHToFile(publicKeySSH, publicFile); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// FromPEMFiles loads a key pair from separate private and public key files in PEM format.
// The function reads both files and reconstructs the appropriate KeyPair type.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateFile: Path to the private key PEM file
//   - publicFile: Path to the public key PEM file
//
// Returns the reconstructed key pair or an error if reading or parsing fails.
//
// Example:
//
//	rsaKeyPair, err := FromPEMFiles[*algo.RSAKeyPair]("private.pem", "public.pem")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func FromPEMFiles[K KeyPair](privateFile, publicFile string) (K, error) {
	var zero K

	// Read private key file
	privateData, err := os.ReadFile(privateFile)
	if err != nil {
		return zero, fmt.Errorf("failed to read private key file %s: %w", privateFile, err)
	}

	// Read public key file
	publicData, err := os.ReadFile(publicFile)
	if err != nil {
		return zero, fmt.Errorf("failed to read public key file %s: %w", publicFile, err)
	}

	// Parse private key to determine type
	privatePEM := format.PEM(privateData)
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return zero, fmt.Errorf("failed to decode private key PEM from %s", privateFile)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse private key from %s: %w", privateFile, err)
	}

	// Parse public key
	publicPEM := format.PEM(publicData)
	publicBlock, _ := pem.Decode(publicPEM)
	if publicBlock == nil {
		return zero, fmt.Errorf("failed to decode public key PEM from %s", publicFile)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return zero, fmt.Errorf("failed to parse public key from %s: %w", publicFile, err)
	}

	// Reconstruct KeyPair based on private key type
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		if rsaPub, ok := publicKey.(*rsa.PublicKey); ok {
			keyPair := &algo.RSAKeyPair{
				PrivateKey: priv,
				PublicKey:  rsaPub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	case *ecdsa.PrivateKey:
		if ecdsaPub, ok := publicKey.(*ecdsa.PublicKey); ok {
			keyPair := &algo.ECDSAKeyPair{
				PrivateKey: priv,
				PublicKey:  ecdsaPub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	case ed25519.PrivateKey:
		if ed25519Pub, ok := publicKey.(ed25519.PublicKey); ok {
			keyPair := &algo.Ed25519KeyPair{
				PrivateKey: priv,
				PublicKey:  ed25519Pub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	}

	return zero, fmt.Errorf("key type mismatch or unsupported key type")
}

// FromDERFiles loads a key pair from separate private and public key files in DER format.
// The function reads both files and reconstructs the appropriate KeyPair type.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateFile: Path to the private key DER file
//   - publicFile: Path to the public key DER file
//
// Returns the reconstructed key pair or an error if reading or parsing fails.
//
// Example:
//
//	ecdsaKeyPair, err := FromDERFiles[*algo.ECDSAKeyPair]("private.der", "public.der")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func FromDERFiles[K KeyPair](privateFile, publicFile string) (K, error) {
	var zero K

	// Read private key file
	privateData, err := os.ReadFile(privateFile)
	if err != nil {
		return zero, fmt.Errorf("failed to read private key file %s: %w", privateFile, err)
	}

	// Read public key file
	publicData, err := os.ReadFile(publicFile)
	if err != nil {
		return zero, fmt.Errorf("failed to read public key file %s: %w", publicFile, err)
	}

	// Parse private key to determine type
	privateDER := format.DER(privateData)
	privateKey, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return zero, fmt.Errorf("failed to parse private key from %s: %w", privateFile, err)
	}

	// Parse public key
	publicDER := format.DER(publicData)
	publicKey, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return zero, fmt.Errorf("failed to parse public key from %s: %w", publicFile, err)
	}

	// Reconstruct KeyPair based on private key type
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		if rsaPub, ok := publicKey.(*rsa.PublicKey); ok {
			keyPair := &algo.RSAKeyPair{
				PrivateKey: priv,
				PublicKey:  rsaPub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	case *ecdsa.PrivateKey:
		if ecdsaPub, ok := publicKey.(*ecdsa.PublicKey); ok {
			keyPair := &algo.ECDSAKeyPair{
				PrivateKey: priv,
				PublicKey:  ecdsaPub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	case ed25519.PrivateKey:
		if ed25519Pub, ok := publicKey.(ed25519.PublicKey); ok {
			keyPair := &algo.Ed25519KeyPair{
				PrivateKey: priv,
				PublicKey:  ed25519Pub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	}

	return zero, fmt.Errorf("key type mismatch or unsupported key type")
}

// FromSSHFiles loads a key pair from separate private and public key files in SSH format.
// The function reads both files and reconstructs the appropriate KeyPair type.
//
// Type parameter:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - privateFile: Path to the SSH private key file
//   - publicFile: Path to the SSH public key file
//   - passphrase: Passphrase for encrypted private keys (empty string for unencrypted)
//
// Returns the reconstructed key pair or an error if reading or parsing fails.
//
// Example:
//
//	ed25519KeyPair, err := FromSSHFiles[*algo.Ed25519KeyPair]("id_ed25519", "id_ed25519.pub", "passphrase")
//	if err != nil {
//		log.Printf("Failed to load key pair: %v", err)
//	}
func FromSSHFiles[K KeyPair](privateFile, publicFile string, passphrase string) (K, error) {
	var zero K

	// Read private key file
	privateData, err := os.ReadFile(privateFile)
	if err != nil {
		return zero, fmt.Errorf("failed to read private key file %s: %w", privateFile, err)
	}

	// Read public key file
	publicData, err := os.ReadFile(publicFile)
	if err != nil {
		return zero, fmt.Errorf("failed to read public key file %s: %w", publicFile, err)
	}

	// Parse private key to determine type
	privateSSH := format.SSH(privateData)
	var privateKey interface{}

	if passphrase == "" {
		privateKey, err = ssh.ParseRawPrivateKey([]byte(privateSSH))
	} else {
		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(privateSSH), []byte(passphrase))
	}

	if err != nil {
		return zero, fmt.Errorf("failed to parse private key from %s: %w", privateFile, err)
	}

	// Parse public key
	publicSSH := format.SSH(publicData)
	sshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicSSH))
	if err != nil {
		return zero, fmt.Errorf("failed to parse public key from %s: %w", publicFile, err)
	}

	// Extract crypto.PublicKey
	var publicKey interface{}
	if cryptoKey, ok := sshPublicKey.(ssh.CryptoPublicKey); ok {
		publicKey = cryptoKey.CryptoPublicKey()
	} else {
		return zero, fmt.Errorf("cannot extract crypto public key from SSH key")
	}

	// Reconstruct KeyPair based on private key type
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		if rsaPub, ok := publicKey.(*rsa.PublicKey); ok {
			keyPair := &algo.RSAKeyPair{
				PrivateKey: priv,
				PublicKey:  rsaPub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	case *ecdsa.PrivateKey:
		if ecdsaPub, ok := publicKey.(*ecdsa.PublicKey); ok {
			keyPair := &algo.ECDSAKeyPair{
				PrivateKey: priv,
				PublicKey:  ecdsaPub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	case ed25519.PrivateKey:
		if ed25519Pub, ok := publicKey.(ed25519.PublicKey); ok {
			keyPair := &algo.Ed25519KeyPair{
				PrivateKey: priv,
				PublicKey:  ed25519Pub,
			}
			if result, ok := any(keyPair).(K); ok {
				return result, nil
			}
		}
	}

	return zero, fmt.Errorf("key type mismatch or unsupported key type")
}

// GetPrivateKeyFromKeyPair extracts the private key from a KeyPair with type safety.
// This function works with all supported KeyPair types and maintains type relationships.
//
// Type parameters:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - keyPair: The key pair from which to extract the private key
//
// Returns the corresponding private key or an error if extraction fails or type mismatch occurs.
//
// Examples:
//
//	// Extract RSA private key with explicit types
//	rsaPriv, err := GetPrivateKeyFromKeyPair[*algo.RSAKeyPair, *rsa.PrivateKey](rsaKeyPair)
//
//	// Extract ECDSA private key with type inference
//	ecdsaPriv, err := GetPrivateKeyFromKeyPair[*algo.ECDSAKeyPair, *ecdsa.PrivateKey](ecdsaKeyPair)
//
//	// Extract Ed25519 private key
//	ed25519Priv, err := GetPrivateKeyFromKeyPair[*algo.Ed25519KeyPair, ed25519.PrivateKey](ed25519KeyPair)
func GetPrivateKeyFromKeyPair[K KeyPair, T PrivateKey](keyPair K) (T, error) {
	var zero T

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		if priv, ok := any(kp.PrivateKey).(T); ok {
			return priv, nil
		}
	case *algo.ECDSAKeyPair:
		if priv, ok := any(kp.PrivateKey).(T); ok {
			return priv, nil
		}
	case *algo.Ed25519KeyPair:
		if priv, ok := any(kp.PrivateKey).(T); ok {
			return priv, nil
		}
	}

	return zero, fmt.Errorf("unsupported key pair type or type mismatch")
}

// GetPublicKeyFromKeyPair extracts the public key from a KeyPair with type safety.
// This function works with all supported KeyPair types and maintains type relationships.
//
// Type parameters:
//   - K: KeyPair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - keyPair: The key pair from which to extract the public key
//
// Returns the corresponding public key or an error if extraction fails or type mismatch occurs.
//
// Examples:
//
//	// Extract RSA public key with explicit types
//	rsaPub, err := GetPublicKeyFromKeyPair[*algo.RSAKeyPair, *rsa.PublicKey](rsaKeyPair)
//
//	// Extract ECDSA public key with type inference
//	ecdsaPub, err := GetPublicKeyFromKeyPair[*algo.ECDSAKeyPair, *ecdsa.PublicKey](ecdsaKeyPair)
//
//	// Extract Ed25519 public key
//	ed25519Pub, err := GetPublicKeyFromKeyPair[*algo.Ed25519KeyPair, ed25519.PublicKey](ed25519KeyPair)
func GetPublicKeyFromKeyPair[K KeyPair, T PublicKey](keyPair K) (T, error) {
	var zero T

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		if pub, ok := any(kp.PublicKey).(T); ok {
			return pub, nil
		}
	case *algo.ECDSAKeyPair:
		if pub, ok := any(kp.PublicKey).(T); ok {
			return pub, nil
		}
	case *algo.Ed25519KeyPair:
		if pub, ok := any(kp.PublicKey).(T); ok {
			return pub, nil
		}
	}

	return zero, fmt.Errorf("unsupported key pair type or type mismatch")
}

// saveDERToFile saves DER-encoded data to a file with secure permissions.
// This is an internal helper function that handles directory creation and file permissions.
//
// Parameters:
//   - derData: DER-encoded data to save
//   - filename: Target file path
//
// The function:
//   - Creates parent directories with 0700 permissions
//   - Checks write permissions for existing files
//   - Saves files with 0600 permissions (owner read/write only)
//
// Returns an error if file operations fail.
func saveDERToFile(derData format.DER, filename string) error {
	dir := filepath.Dir(filename)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if _, err := os.Stat(filename); err == nil {
		file, err := os.OpenFile(filename, os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("no write permission for existing file %s: %w", filename, err)
		}
		file.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check file status %s: %w", filename, err)
	}

	if err := os.WriteFile(filename, derData, 0o600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}

// saveSSHToFile saves SSH-encoded data to a file with secure permissions.
// This is an internal helper function that handles directory creation and file permissions.
//
// Parameters:
//   - sshData: SSH-encoded data to save
//   - filename: Target file path
//
// The function:
//   - Creates parent directories with 0700 permissions
//   - Checks write permissions for existing files
//   - Saves files with 0600 permissions (owner read/write only)
//
// Returns an error if file operations fail.
func saveSSHToFile(sshData format.SSH, filename string) error {
	dir := filepath.Dir(filename)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if _, err := os.Stat(filename); err == nil {
		file, err := os.OpenFile(filename, os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("no write permission for existing file %s: %w", filename, err)
		}
		file.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check file status %s: %w", filename, err)
	}

	if err := os.WriteFile(filename, []byte(sshData), 0o600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}

// savePEMToFile saves PEM-encoded data to a file with secure permissions.
// This is an internal helper function that handles directory creation and file permissions.
//
// Parameters:
//   - pemData: PEM-encoded data to save
//   - filename: Target file path
//
// The function:
//   - Creates parent directories with 0700 permissions
//   - Checks write permissions for existing files
//   - Saves files with 0600 permissions (owner read/write only)
//
// Returns an error if file operations fail.
func savePEMToFile(pemData format.PEM, filename string) error {
	dir := filepath.Dir(filename)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if _, err := os.Stat(filename); err == nil {
		file, err := os.OpenFile(filename, os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("no write permission for existing file %s: %w", filename, err)
		}
		file.Close()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check file status %s: %w", filename, err)
	}

	if err := os.WriteFile(filename, pemData, 0o600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}
