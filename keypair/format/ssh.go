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

var (
	sshPublicKeyRegex = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ecdsa-sha2-[a-z0-9]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$`)
)

func PublicKeyToSSH[T keypair.PublicKey](publicKey T, comment string) (string, error) {
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

	return sshStr, nil
}

func ParsePublicKeyFromSSH[T keypair.PublicKey](sshData string) (T, error) {
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

func PrivateKeyToSSH[T keypair.PrivateKey](privateKey T, comment string, passphrase string) (string, error) {
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
	return string(sshPrivateKey), nil
}

func ParsePrivateKeyFromSSH[T keypair.PrivateKey](sshData string, passphrase string) (T, error) {
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

type SSHPublicKeyInfo struct {
	Algorithm string
	KeyData   string
	Comment   string
}

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

func ConvertPEMToSSH(pemData keypair.PEM, comment string, isPrivate bool) (string, error) {
	if isPrivate {
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

func ConvertDERToSSH(derData []byte, comment string, isPrivate bool) (string, error) {
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

func ConvertSSHToPEM(sshData string, isPrivate bool, passphrase string) (keypair.PEM, error) {
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

func ConvertSSHToDER(sshData string, isPrivate bool, passphrase string) ([]byte, error) {
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
