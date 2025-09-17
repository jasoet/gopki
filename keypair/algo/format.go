package algo

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

type PEM []byte
type DER []byte
type SSH string


// ConvertPEMToDER converts PEM-encoded key data to DER binary format.
func ConvertPEMToDER(pemData PEM) (DER, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return DER(block.Bytes), nil
}

// ConvertDERToPEM converts DER binary data to PEM format with appropriate headers.
func ConvertDERToPEM(derData DER, keyType string) (PEM, error) {
	var blockType string
	if isPrivateKeyDER(derData) {
		blockType = "PRIVATE KEY"
	} else {
		blockType = "PUBLIC KEY"
	}

	pemBlock := &pem.Block{
		Type:  blockType,
		Bytes: derData,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if pemData == nil {
		return nil, fmt.Errorf("failed to encode DER to PEM")
	}
	return PEM(pemData), nil
}

// isPrivateKeyDER determines if DER data contains a private key.
func isPrivateKeyDER(derData DER) bool {
	_, err := x509.ParsePKCS8PrivateKey(derData)
	return err == nil
}

// ============================================================================
// Format-Specific Generic Types Implementation
// ============================================================================

// PEMFormat represents PEM-encoded key data with type-safe parsing methods
type PEMFormat struct {
	Data PEM
}

// DERFormat represents DER-encoded key data with type-safe parsing methods
type DERFormat struct {
	Data DER
}

// SSHFormat represents SSH-encoded key data with type-safe parsing methods
type SSHFormat struct {
	Data SSH
}

// Format returns the format name for PEMFormat
func (p PEMFormat) Format() string {
	return "PEM"
}

// Format returns the format name for DERFormat
func (d DERFormat) Format() string {
	return "DER"
}

// Format returns the format name for SSHFormat
func (s SSHFormat) Format() string {
	return "SSH"
}

// ParseRSA parses PEM data as RSA key pair
func (p PEMFormat) ParseRSA() (*RSAKeyPair, error) {
	return RSAKeyPairFromPEM(p.Data)
}

// ParseECDSA parses PEM data as ECDSA key pair
func (p PEMFormat) ParseECDSA() (*ECDSAKeyPair, error) {
	return ECDSAKeyPairFromPEM(p.Data)
}

// ParseEd25519 parses PEM data as Ed25519 key pair
func (p PEMFormat) ParseEd25519() (*Ed25519KeyPair, error) {
	return Ed25519KeyPairFromPEM(p.Data)
}

// ParseRSA parses DER data as RSA key pair
func (d DERFormat) ParseRSA() (*RSAKeyPair, error) {
	return RSAKeyPairFromDER(d.Data)
}

// ParseECDSA parses DER data as ECDSA key pair
func (d DERFormat) ParseECDSA() (*ECDSAKeyPair, error) {
	return ECDSAKeyPairFromDER(d.Data)
}

// ParseEd25519 parses DER data as Ed25519 key pair
func (d DERFormat) ParseEd25519() (*Ed25519KeyPair, error) {
	return Ed25519KeyPairFromDER(d.Data)
}

// ParseRSA parses SSH data as RSA key pair
func (s SSHFormat) ParseRSA(passphrase string) (*RSAKeyPair, error) {
	return RSAKeyPairFromSSH(s.Data, passphrase)
}

// ParseECDSA parses SSH data as ECDSA key pair
func (s SSHFormat) ParseECDSA(passphrase string) (*ECDSAKeyPair, error) {
	return ECDSAKeyPairFromSSH(s.Data, passphrase)
}

// ParseEd25519 parses SSH data as Ed25519 key pair
func (s SSHFormat) ParseEd25519(passphrase string) (*Ed25519KeyPair, error) {
	return Ed25519KeyPairFromSSH(s.Data, passphrase)
}

// ToDER converts PEM format to DER format
func (p PEMFormat) ToDER() (DERFormat, error) {
	derData, err := ConvertPEMToDER(p.Data)
	if err != nil {
		return DERFormat{}, err
	}
	return DERFormat{Data: derData}, nil
}

// ToPEM converts DER format to PEM format
func (d DERFormat) ToPEM() (PEMFormat, error) {
	pemData, err := ConvertDERToPEM(d.Data, "")
	if err != nil {
		return PEMFormat{}, err
	}
	return PEMFormat{Data: pemData}, nil
}

// AutoFormat automatically detects format and returns appropriate typed format wrapper
func AutoFormat(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	dataStr := string(data)

	// Detect SSH formats first (most specific)
	if strings.Contains(dataStr, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return SSHFormat{Data: SSH(data)}, nil
	}

	if strings.HasPrefix(dataStr, "ssh-rsa ") ||
		strings.HasPrefix(dataStr, "ssh-ed25519 ") ||
		strings.HasPrefix(dataStr, "ecdsa-sha2-") {
		return SSHFormat{Data: SSH(data)}, nil
	}

	// Detect PEM format
	if strings.HasPrefix(dataStr, "-----BEGIN") {
		return PEMFormat{Data: PEM(data)}, nil
	}

	// Detect DER format (binary data)
	if !isPrintableText(data) && len(data) > 50 {
		return DERFormat{Data: DER(data)}, nil
	}

	return nil, fmt.Errorf("unable to detect format")
}

// isPrintableText determines if the given data consists primarily of printable text.
func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printableCount := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}

	return float64(printableCount)/float64(len(data)) > 0.95
}

