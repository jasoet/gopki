package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// SimpleEd25519PKCS7 creates a minimal working Ed25519 PKCS#7 signature for testing
func SimpleEd25519PKCS7(data []byte, privateKey ed25519.PrivateKey, certificate *x509.Certificate) ([]byte, error) {
	// For now, let's create a minimal structure that we can verify works
	// This is a temporary implementation to test the integration

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}

	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	// Create Ed25519 signature
	signature := ed25519.Sign(privateKey, data)

	// Create a simple PKCS#7-like structure for testing
	// This is a placeholder that embeds the signature and certificate
	result := make([]byte, 0, len(signature)+len(certificate.Raw)+100)

	// Add a simple header to identify this as our Ed25519 PKCS#7
	header := []byte("ED25519-PKCS7-V1:")
	result = append(result, header...)

	// Add certificate length and certificate
	certLen := len(certificate.Raw)
	result = append(result, byte(certLen>>24), byte(certLen>>16), byte(certLen>>8), byte(certLen))
	result = append(result, certificate.Raw...)

	// Add signature length and signature
	sigLen := len(signature)
	result = append(result, byte(sigLen>>24), byte(sigLen>>16), byte(sigLen>>8), byte(sigLen))
	result = append(result, signature...)

	return result, nil
}

// VerifySimpleEd25519PKCS7 verifies our simple Ed25519 PKCS#7 signature
func VerifySimpleEd25519PKCS7(data []byte, pkcs7Data []byte) (*Ed25519PKCS7Info, error) {
	header := []byte("ED25519-PKCS7-V1:")
	if len(pkcs7Data) < len(header) {
		return nil, fmt.Errorf("invalid PKCS#7 data: too short")
	}

	// Check header
	if string(pkcs7Data[:len(header)]) != string(header) {
		return nil, fmt.Errorf("not a simple Ed25519 PKCS#7 signature")
	}

	offset := len(header)

	// Read certificate length
	if len(pkcs7Data) < offset+4 {
		return nil, fmt.Errorf("invalid PKCS#7 data: missing certificate length")
	}
	certLen := int(pkcs7Data[offset])<<24 | int(pkcs7Data[offset+1])<<16 | int(pkcs7Data[offset+2])<<8 | int(pkcs7Data[offset+3])
	offset += 4

	// Read certificate
	if len(pkcs7Data) < offset+certLen {
		return nil, fmt.Errorf("invalid PKCS#7 data: missing certificate")
	}
	certData := pkcs7Data[offset : offset+certLen]
	offset += certLen

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Read signature length
	if len(pkcs7Data) < offset+4 {
		return nil, fmt.Errorf("invalid PKCS#7 data: missing signature length")
	}
	sigLen := int(pkcs7Data[offset])<<24 | int(pkcs7Data[offset+1])<<16 | int(pkcs7Data[offset+2])<<8 | int(pkcs7Data[offset+3])
	offset += 4

	// Read signature
	if len(pkcs7Data) < offset+sigLen {
		return nil, fmt.Errorf("invalid PKCS#7 data: missing signature")
	}
	signature := pkcs7Data[offset : offset+sigLen]

	// Verify signature
	ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain Ed25519 public key")
	}

	if !ed25519.Verify(ed25519PubKey, data, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return &Ed25519PKCS7Info{
		Certificate: cert,
		Signature:   signature,
		Verified:    true,
	}, nil
}

// IsSimpleEd25519PKCS7 checks if data is our simple format
func IsSimpleEd25519PKCS7(pkcs7Data []byte) bool {
	header := []byte("ED25519-PKCS7-V1:")
	if len(pkcs7Data) < len(header) {
		return false
	}
	return string(pkcs7Data[:len(header)]) == string(header)
}

// DebugPKCS7Structure helps debug PKCS#7 structures
func DebugPKCS7Structure(data []byte) string {
	if len(data) > 100 {
		return fmt.Sprintf("PKCS#7 data (%d bytes): %s...", len(data), hex.EncodeToString(data[:100]))
	}
	return fmt.Sprintf("PKCS#7 data (%d bytes): %s", len(data), hex.EncodeToString(data))
}
