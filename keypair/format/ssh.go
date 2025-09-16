package format

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"github.com/jasoet/gopki/keypair"
	"golang.org/x/crypto/ssh"
)

// SSH format constants define the standard SSH key type identifiers
// used in SSH public key formats and authorized_keys files.
const (
	// SSHRSAType is the SSH identifier for RSA public keys
	SSHRSAType = "ssh-rsa"
	// SSHEd25519Type is the SSH identifier for Ed25519 public keys
	SSHEd25519Type = "ssh-ed25519"
	// SSHECDSAPrefix is the common prefix for ECDSA SSH key types (e.g., ecdsa-sha2-nistp256)
	SSHECDSAPrefix = "ecdsa-sha2-"
)

var (
	// sshPublicKeyRegex parses SSH public key format: "algorithm base64-key [comment]"
	// Groups: 1=algorithm, 2=base64 key data, 3=optional comment
	sshPublicKeyRegex = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ecdsa-sha2-[a-z0-9]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$`)
)

// PublicKeyToSSH converts a cryptographic public key to SSH public key format.
// The SSH format is used in authorized_keys files and for key identification.
//
// Type parameter:
//   - T: Public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - publicKey: The public key to convert
//   - comment: Optional comment to include in the SSH key (commonly username@hostname)
//
// Returns:
//   - String in SSH public key format: "algorithm base64-key [comment]"
//   - Error if conversion fails
//
// Example:
//
//	sshKey, err := PublicKeyToSSH(rsaPublicKey, "user@example.com")
//	if err != nil {
//		log.Printf("SSH conversion failed: %v", err)
//	}
func PublicKeyToSSH[T keypair.PublicKey](publicKey T, comment string) (keypair.SSH, error) {
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", NewFormatError(FormatSSH, "failed to convert to SSH public key", err)
	}

	sshData := ssh.MarshalAuthorizedKey(sshPubKey)
	sshStr := strings.TrimSpace(string(sshData))

	if comment != "" && !strings.Contains(sshStr, comment) {
		parts := strings.SplitN(sshStr, " ", 3)
		if len(parts) >= 2 {
			sshStr = parts[0] + " " + parts[1] + " " + comment
		}
	}

	return keypair.SSH(sshStr), nil
}

// ParsePublicKeyFromSSH parses a public key from SSH public key format.
// This function can parse keys from authorized_keys files or SSH key strings.
//
// Type parameter:
//   - T: Expected public key type (*rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey)
//
// Parameters:
//   - sshData: SSH public key string in format "algorithm base64-key [comment]"
//
// Returns:
//   - The parsed public key of the specified type
//   - Error if parsing fails or key type doesn't match
//
// Example:
//
//	rsaKey, err := ParsePublicKeyFromSSH[*rsa.PublicKey]("ssh-rsa AAAAB3... user@host")
//	if err != nil {
//		log.Printf("SSH key parsing failed: %v", err)
//	}
func ParsePublicKeyFromSSH[T keypair.PublicKey](sshData keypair.SSH) (T, error) {
	var zero T

	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshData))
	if err != nil {
		return zero, NewFormatError(FormatSSH, "failed to parse SSH public key", err)
	}

	cryptoKey := sshPubKey.(ssh.CryptoPublicKey).CryptoPublicKey()

	typedKey, ok := cryptoKey.(T)
	if !ok {
		return zero, NewFormatError(FormatSSH, fmt.Sprintf("SSH public key is not of expected type %T", zero), nil)
	}

	return typedKey, nil
}

// PrivateKeyToSSH converts a cryptographic private key to OpenSSH private key format.
// This format is used by OpenSSH for storing private keys, with optional passphrase protection.
//
// Type parameter:
//   - T: Private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - privateKey: The private key to convert
//   - comment: Optional comment to embed in the key file
//   - passphrase: Optional passphrase for key encryption (empty string for unencrypted)
//
// Returns:
//   - String containing the OpenSSH private key in PEM format
//   - Error if conversion fails
//
// Security note: Using a passphrase is recommended for private key storage.
//
// Example:
//
//	sshKey, err := PrivateKeyToSSH(rsaPrivateKey, "my-key", "secure-passphrase")
//	if err != nil {
//		log.Printf("SSH conversion failed: %v", err)
//	}
func PrivateKeyToSSH[T keypair.PrivateKey](privateKey T, comment string, passphrase string) (keypair.SSH, error) {
	var pemBlock *pem.Block
	var err error

	if passphrase == "" {
		pemBlock, err = ssh.MarshalPrivateKey(privateKey, comment)
	} else {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, []byte(passphrase))
	}

	if err != nil {
		return "", NewFormatError(FormatSSH, "failed to marshal SSH private key", err)
	}

	sshPrivateKey := pem.EncodeToMemory(pemBlock)
	return keypair.SSH(sshPrivateKey), nil
}

// ParsePrivateKeyFromSSH parses a private key from OpenSSH private key format.
// This function handles both encrypted and unencrypted OpenSSH private keys.
//
// Type parameter:
//   - T: Expected private key type (*rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Parameters:
//   - sshData: OpenSSH private key data (typically from a file like id_rsa)
//   - passphrase: Passphrase for encrypted keys (empty string for unencrypted)
//
// Returns:
//   - The parsed private key of the specified type
//   - Error if parsing fails, wrong passphrase, or key type doesn't match
//
// Note: The function handles the Ed25519 pointer/value type conversion automatically.
//
// Example:
//
//	rsaKey, err := ParsePrivateKeyFromSSH[*rsa.PrivateKey](sshKeyData, "passphrase")
//	if err != nil {
//		log.Printf("SSH key parsing failed: %v", err)
//	}
func ParsePrivateKeyFromSSH[T keypair.PrivateKey](sshData keypair.SSH, passphrase string) (T, error) {
	var zero T

	// Parse the SSH private key using ParseRawPrivateKey
	var rawKey interface{}
	var err error

	if passphrase == "" {
		rawKey, err = ssh.ParseRawPrivateKey([]byte(sshData))
	} else {
		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshData), []byte(passphrase))
	}

	if err != nil {
		return zero, NewFormatError(FormatSSH, "failed to parse SSH private key", err)
	}

	// Handle Ed25519 special case - ParseRawPrivateKey returns *ed25519.PrivateKey
	// but we might need ed25519.PrivateKey (value type)
	if ed25519Key, ok := rawKey.(*ed25519.PrivateKey); ok {
		// Try both pointer and value forms
		if typedKey, ok := interface{}(ed25519Key).(T); ok {
			return typedKey, nil
		}
		if typedKey, ok := interface{}(*ed25519Key).(T); ok {
			return typedKey, nil
		}
	}

	// Type assertion for other key types
	typedKey, ok := rawKey.(T)
	if !ok {
		return zero, NewFormatError(FormatSSH, fmt.Sprintf("SSH private key is not of expected type %T, got %T", zero, rawKey), nil)
	}

	return typedKey, nil
}

// SSHPublicKeyInfo contains the parsed components of an SSH public key.
// This structure provides easy access to the individual parts of an SSH key string.
type SSHPublicKeyInfo struct {
	Algorithm string // The key algorithm (ssh-rsa, ssh-ed25519, ecdsa-sha2-*)
	KeyData   string // The Base64-encoded key data
	Comment   string // Optional comment (often username@hostname)
}

// ParseSSHPublicKeyInfo parses an SSH public key string into its component parts.
// This function extracts the algorithm, key data, and optional comment without
// performing cryptographic validation.
//
// Parameters:
//   - sshData: SSH public key string in standard format
//
// Returns:
//   - *SSHPublicKeyInfo: Parsed components of the SSH key
//   - Error if the format is invalid
//
// Example:
//
//	info, err := ParseSSHPublicKeyInfo("ssh-rsa AAAAB3... user@host")
//	if err != nil {
//		log.Printf("Invalid SSH key format: %v", err)
//	} else {
//		fmt.Printf("Algorithm: %s, Comment: %s\n", info.Algorithm, info.Comment)
//	}
func ParseSSHPublicKeyInfo(sshData keypair.SSH) (*SSHPublicKeyInfo, error) {
	matches := sshPublicKeyRegex.FindStringSubmatch(strings.TrimSpace(string(sshData)))
	if matches == nil {
		return nil, NewFormatError(FormatSSH, "invalid SSH public key format", nil)
	}

	info := &SSHPublicKeyInfo{
		Algorithm: matches[1],
		KeyData:   matches[2],
	}

	if len(matches) > 3 {
		info.Comment = matches[3]
	}

	return info, nil
}

// GetSSHKeyType maps SSH algorithm names to standardized key type names.
// This function converts SSH-specific algorithm identifiers to common names.
//
// Parameters:
//   - algorithm: SSH algorithm identifier (e.g., "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256")
//
// Returns:
//   - Standardized key type name ("RSA", "ECDSA", "Ed25519", or "Unknown")
//
// Example:
//
//	keyType := GetSSHKeyType("ssh-rsa") // Returns "RSA"
//	keyType := GetSSHKeyType("ecdsa-sha2-nistp256") // Returns "ECDSA"
func GetSSHKeyType(algorithm string) string {
	switch {
	case algorithm == SSHRSAType:
		return "RSA"
	case algorithm == SSHEd25519Type:
		return "Ed25519"
	case strings.HasPrefix(algorithm, SSHECDSAPrefix):
		return "ECDSA"
	default:
		return "Unknown"
	}
}

// ConvertPEMToSSH converts PEM-encoded key data to SSH format.
// This function automatically detects the key algorithm and converts to the appropriate SSH format.
//
// Parameters:
//   - pemData: PEM-encoded key data (PKCS#8 for private keys, PKIX for public keys)
//   - comment: Optional comment to include in SSH format
//   - isPrivate: true for private key conversion, false for public key conversion
//
// Returns:
//   - String containing the key in SSH format
//   - Error if conversion fails or key type is unsupported
//
// The function tries all supported algorithms (RSA, ECDSA, Ed25519) and uses the first successful match.
//
// Example:
//
//	sshKey, err := ConvertPEMToSSH(pemData, "user@host", false) // Convert public key
//	if err != nil {
//		log.Printf("PEM to SSH conversion failed: %v", err)
//	}
func ConvertPEMToSSH(pemData keypair.PEM, comment string, isPrivate bool) (keypair.SSH, error) {
	if isPrivate {
		if rsaKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
			return PrivateKeyToSSH(rsaKey, comment, "")
		} else if ecdsaKey, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
			return PrivateKeyToSSH(ecdsaKey, comment, "")
		} else if ed25519Key, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
			return PrivateKeyToSSH(ed25519Key, comment, "")
		} else {
			return "", NewFormatError(FormatSSH, "unable to parse PEM private key for SSH conversion", nil)
		}
	} else {
		if rsaKey, err := ParsePublicKeyFromPEM[*rsa.PublicKey](pemData); err == nil {
			return PublicKeyToSSH(rsaKey, comment)
		} else if ecdsaKey, err := ParsePublicKeyFromPEM[*ecdsa.PublicKey](pemData); err == nil {
			return PublicKeyToSSH(ecdsaKey, comment)
		} else if ed25519Key, err := ParsePublicKeyFromPEM[ed25519.PublicKey](pemData); err == nil {
			return PublicKeyToSSH(ed25519Key, comment)
		} else {
			return "", NewFormatError(FormatSSH, "unable to parse PEM public key for SSH conversion", nil)
		}
	}
}

func ConvertDERToSSH(derData keypair.DER, comment string, isPrivate bool) (keypair.SSH, error) {
	if isPrivate {
		if rsaKey, err := ParsePrivateKeyFromDER[*rsa.PrivateKey](derData); err == nil {
			return PrivateKeyToSSH(rsaKey, comment, "")
		} else if ecdsaKey, err := ParsePrivateKeyFromDER[*ecdsa.PrivateKey](derData); err == nil {
			return PrivateKeyToSSH(ecdsaKey, comment, "")
		} else if ed25519Key, err := ParsePrivateKeyFromDER[ed25519.PrivateKey](derData); err == nil {
			return PrivateKeyToSSH(ed25519Key, comment, "")
		} else {
			return "", NewFormatError(FormatSSH, "unable to parse DER private key for SSH conversion", nil)
		}
	} else {
		if rsaKey, err := ParsePublicKeyFromDER[*rsa.PublicKey](derData); err == nil {
			return PublicKeyToSSH(rsaKey, comment)
		} else if ecdsaKey, err := ParsePublicKeyFromDER[*ecdsa.PublicKey](derData); err == nil {
			return PublicKeyToSSH(ecdsaKey, comment)
		} else if ed25519Key, err := ParsePublicKeyFromDER[ed25519.PublicKey](derData); err == nil {
			return PublicKeyToSSH(ed25519Key, comment)
		} else {
			return "", NewFormatError(FormatSSH, "unable to parse DER public key for SSH conversion", nil)
		}
	}
}

// ConvertSSHToPEM converts SSH format key data to PEM encoding.
// This function handles both SSH public keys (authorized_keys format) and OpenSSH private keys.
//
// Parameters:
//   - sshData: SSH-formatted key data
//   - isPrivate: true for private key conversion, false for public key conversion
//   - passphrase: Passphrase for encrypted SSH private keys (empty for unencrypted/public keys)
//
// Returns:
//   - PEM-encoded key data
//   - Error if conversion fails or key type is unsupported
//
// The function automatically detects the key algorithm and performs the appropriate conversion.
//
// Example:
//
//	pemData, err := ConvertSSHToPEM(sshKeyData, true, "passphrase") // Convert private key
//	if err != nil {
//		log.Printf("SSH to PEM conversion failed: %v", err)
//	}
func ConvertSSHToPEM(sshData keypair.SSH, isPrivate bool, passphrase string) (keypair.PEM, error) {
	if isPrivate {
		// Try to parse SSH private key and convert to PEM
		if rsaKey, err := ParsePrivateKeyFromSSH[*rsa.PrivateKey](sshData, passphrase); err == nil {
			return keypair.PrivateKeyToPEM(rsaKey)
		} else if ecdsaKey, err := ParsePrivateKeyFromSSH[*ecdsa.PrivateKey](sshData, passphrase); err == nil {
			return keypair.PrivateKeyToPEM(ecdsaKey)
		} else if ed25519Key, err := ParsePrivateKeyFromSSH[ed25519.PrivateKey](sshData, passphrase); err == nil {
			return keypair.PrivateKeyToPEM(ed25519Key)
		} else {
			return nil, NewFormatError(FormatPEM, "unable to parse SSH private key for PEM conversion", nil)
		}
	} else {
		// Handle public key conversion
		if rsaKey, err := ParsePublicKeyFromSSH[*rsa.PublicKey](sshData); err == nil {
			return keypair.PublicKeyToPEM(rsaKey)
		} else if ecdsaKey, err := ParsePublicKeyFromSSH[*ecdsa.PublicKey](sshData); err == nil {
			return keypair.PublicKeyToPEM(ecdsaKey)
		} else if ed25519Key, err := ParsePublicKeyFromSSH[ed25519.PublicKey](sshData); err == nil {
			return keypair.PublicKeyToPEM(ed25519Key)
		} else {
			return nil, NewFormatError(FormatPEM, "unable to parse SSH public key for PEM conversion", nil)
		}
	}
}

func ConvertSSHToDER(sshData keypair.SSH, isPrivate bool, passphrase string) ([]byte, error) {
	if isPrivate {
		// Try to parse SSH private key and convert to DER
		if rsaKey, err := ParsePrivateKeyFromSSH[*rsa.PrivateKey](sshData, passphrase); err == nil {
			return PrivateKeyToDER(rsaKey)
		} else if ecdsaKey, err := ParsePrivateKeyFromSSH[*ecdsa.PrivateKey](sshData, passphrase); err == nil {
			return PrivateKeyToDER(ecdsaKey)
		} else if ed25519Key, err := ParsePrivateKeyFromSSH[ed25519.PrivateKey](sshData, passphrase); err == nil {
			return PrivateKeyToDER(ed25519Key)
		} else {
			return nil, NewFormatError(FormatDER, "unable to parse SSH private key for DER conversion", nil)
		}
	} else {
		// Handle public key conversion
		if rsaKey, err := ParsePublicKeyFromSSH[*rsa.PublicKey](sshData); err == nil {
			return PublicKeyToDER(rsaKey)
		} else if ecdsaKey, err := ParsePublicKeyFromSSH[*ecdsa.PublicKey](sshData); err == nil {
			return PublicKeyToDER(ecdsaKey)
		} else if ed25519Key, err := ParsePublicKeyFromSSH[ed25519.PublicKey](sshData); err == nil {
			return PublicKeyToDER(ed25519Key)
		} else {
			return nil, NewFormatError(FormatDER, "unable to parse SSH public key for DER conversion", nil)
		}
	}
}
