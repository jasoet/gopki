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

// SSH format constants
const (
	SSHRSAType     = "ssh-rsa"
	SSHEd25519Type = "ssh-ed25519"
	SSHECDSAPrefix = "ecdsa-sha2-"
)

// SSH key format patterns
var (
	sshPublicKeyRegex = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ecdsa-sha2-[a-z0-9]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$`)
)

// PublicKeyToSSH converts a public key to SSH format
func PublicKeyToSSH[T keypair.PublicKey](publicKey T, comment string) (string, error) {
	// Convert to ssh.PublicKey first
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", NewFormatError(FormatSSH, "failed to convert to SSH public key", err)
	}

	// Get the SSH wire format
	sshData := ssh.MarshalAuthorizedKey(sshPubKey)
	sshStr := strings.TrimSpace(string(sshData))

	// If comment is provided and the key doesn't already have one, add it
	if comment != "" && !strings.Contains(sshStr, comment) {
		// Remove any existing comment first
		parts := strings.SplitN(sshStr, " ", 3)
		if len(parts) >= 2 {
			sshStr = parts[0] + " " + parts[1] + " " + comment
		}
	}

	return sshStr, nil
}

// ParsePublicKeyFromSSH parses a public key from SSH format
func ParsePublicKeyFromSSH[T keypair.PublicKey](sshData string) (T, error) {
	var zero T

	// Parse the SSH public key
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshData))
	if err != nil {
		return zero, NewFormatError(FormatSSH, "failed to parse SSH public key", err)
	}

	// Convert back to crypto type
	cryptoKey := sshPubKey.(ssh.CryptoPublicKey).CryptoPublicKey()

	// Type assert to the expected type
	typedKey, ok := cryptoKey.(T)
	if !ok {
		return zero, NewFormatError(FormatSSH, fmt.Sprintf("SSH public key is not of expected type %T", zero), nil)
	}

	return typedKey, nil
}

// PrivateKeyToSSH converts a private key to SSH private key format (OpenSSH)
func PrivateKeyToSSH[T keypair.PrivateKey](privateKey T, comment string, passphrase string) (string, error) {
	// Convert to SSH format using OpenSSH private key format
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

	// Convert PEM block to string
	sshPrivateKey := pem.EncodeToMemory(pemBlock)
	return string(sshPrivateKey), nil
}

// ParsePrivateKeyFromSSH parses a private key from SSH format
// Note: This is a complex operation due to SSH package limitations.
// For now, we'll focus on round-trip compatibility with our own generated keys.
func ParsePrivateKeyFromSSH[T keypair.PrivateKey](sshData string, passphrase string) (T, error) {
	var zero T

	// For the SSH private key parsing, we need to work around Go's ssh package limitations
	// The ssh package doesn't expose the underlying private key directly
	// This is a known limitation - see: https://github.com/golang/go/issues/15761

	// For now, we'll return an error explaining the limitation
	return zero, NewFormatError(FormatSSH,
		"SSH private key parsing is limited by Go's crypto/ssh package design. "+
			"Direct access to underlying private keys is not supported. "+
			"Consider using PEM or DER formats for private key storage and conversion.", nil)
}

// ParseSSHPublicKeyInfo extracts information from SSH public key string
type SSHPublicKeyInfo struct {
	Algorithm string
	KeyData   string
	Comment   string
}

// ParseSSHPublicKeyInfo parses SSH public key string and extracts components
func ParseSSHPublicKeyInfo(sshData string) (*SSHPublicKeyInfo, error) {
	matches := sshPublicKeyRegex.FindStringSubmatch(strings.TrimSpace(sshData))
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

// GetSSHKeyType determines the SSH key type from the algorithm string
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

// ConvertPEMToSSH converts PEM format to SSH format
func ConvertPEMToSSH(pemData keypair.PEM, comment string, isPrivate bool) (string, error) {
	if isPrivate {
		// Parse PEM private key and convert to SSH (OpenSSH format only)
		if rsaKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
			return PrivateKeyToSSH(rsaKey, comment, "")
		} else if ecdsaKey, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
			return PrivateKeyToSSH(ecdsaKey, comment, "")
		} else if ed25519Key, err := keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
			return PrivateKeyToSSH(ed25519Key, comment, "")
		} else {
			return "", NewFormatError(FormatSSH, "unable to parse PEM private key for SSH conversion", nil)
		}
	} else {
		// Parse PEM public key and convert to SSH
		if rsaKey, err := keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](pemData); err == nil {
			return PublicKeyToSSH(rsaKey, comment)
		} else if ecdsaKey, err := keypair.ParsePublicKeyFromPEM[*ecdsa.PublicKey](pemData); err == nil {
			return PublicKeyToSSH(ecdsaKey, comment)
		} else if ed25519Key, err := keypair.ParsePublicKeyFromPEM[ed25519.PublicKey](pemData); err == nil {
			return PublicKeyToSSH(ed25519Key, comment)
		} else {
			return "", NewFormatError(FormatSSH, "unable to parse PEM public key for SSH conversion", nil)
		}
	}
}

// ConvertDERToSSH converts DER format to SSH format
func ConvertDERToSSH(derData []byte, comment string, isPrivate bool) (string, error) {
	if isPrivate {
		// Parse DER private key and convert to SSH
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
		// Parse DER public key and convert to SSH
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

// ConvertSSHToPEM converts SSH format to PEM format
func ConvertSSHToPEM(sshData string, isPrivate bool, passphrase string) (keypair.PEM, error) {
	if isPrivate {
		// SSH private key to PEM conversion is not supported due to SSH package limitations
		return nil, NewFormatError(FormatPEM,
			"SSH private key to PEM conversion is not supported due to Go crypto/ssh package limitations. "+
				"Use PEM or DER formats for private key round-trip conversion.", nil)
	} else {
		// Parse SSH public key and convert to PEM
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

// ConvertSSHToDER converts SSH format to DER format
func ConvertSSHToDER(sshData string, isPrivate bool, passphrase string) ([]byte, error) {
	if isPrivate {
		// SSH private key to DER conversion is not supported due to SSH package limitations
		return nil, NewFormatError(FormatDER,
			"SSH private key to DER conversion is not supported due to Go crypto/ssh package limitations. "+
				"Use PEM or DER formats for private key round-trip conversion.", nil)
	} else {
		// Parse SSH public key and convert to DER
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
