package compatibility

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeyPair represents a generated key pair for testing
type TestKeyPair struct {
	Algorithm  string
	KeySize    int
	CurveName  string
	PrivateKey interface{}
	PublicKey  interface{}
	PrivatePEM []byte
	PublicPEM  []byte
	PrivateDER []byte
	PublicDER  []byte
	TempDir    string
}

// Cleanup removes temporary files created during testing
func (tkp *TestKeyPair) Cleanup() {
	if tkp.TempDir != "" {
		os.RemoveAll(tkp.TempDir)
	}
}

// OpenSSLHelper provides utilities for OpenSSL command execution
type OpenSSLHelper struct {
	t       *testing.T
	tempDir string
}

// NewOpenSSLHelper creates a new OpenSSL helper instance
func NewOpenSSLHelper(t *testing.T) *OpenSSLHelper {
	tempDir, err := os.MkdirTemp("", "gopki_openssl_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	return &OpenSSLHelper{
		t:       t,
		tempDir: tempDir,
	}
}

// Cleanup removes temporary files
func (h *OpenSSLHelper) Cleanup() {
	os.RemoveAll(h.tempDir)
}

// TempFile creates a temporary file with the given content
func (h *OpenSSLHelper) TempFile(name string, content []byte) string {
	filepath := filepath.Join(h.tempDir, name)
	err := os.WriteFile(filepath, content, 0600)
	if err != nil {
		h.t.Fatalf("Failed to write temp file %s: %v", filepath, err)
	}
	return filepath
}

// RunOpenSSL executes an OpenSSL command and returns the output
func (h *OpenSSLHelper) RunOpenSSL(args ...string) ([]byte, error) {
	cmd := exec.Command("openssl", args...)

	// Log the command being executed
	h.t.Logf("    → Executing: openssl %s", strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ Command failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return output, fmt.Errorf("openssl command failed: %v, output: %s", err, string(output))
	}

	// Log successful execution
	if len(output) > 0 && len(output) < 200 {
		h.t.Logf("    ✓ Success: %s", strings.TrimSpace(string(output)))
	} else if len(output) > 0 {
		h.t.Logf("    ✓ Success: generated %d bytes of output", len(output))
	} else {
		h.t.Logf("    ✓ Success: command completed")
	}

	return output, nil
}

// GenerateRSAWithOpenSSL generates an RSA key pair using OpenSSL
func (h *OpenSSLHelper) GenerateRSAWithOpenSSL(keySize int) (privateKeyPEM, publicKeyPEM []byte, err error) {
	h.t.Logf("    → Generating RSA-%d key pair with OpenSSL...", keySize)

	// Generate private key
	privKeyFile := filepath.Join(h.tempDir, "rsa_private.pem")
	pubKeyFile := filepath.Join(h.tempDir, "rsa_public.pem")

	// Generate private key
	_, err = h.RunOpenSSL("genpkey", "-algorithm", "RSA",
		"-out", privKeyFile, "-pkeyopt", fmt.Sprintf("rsa_keygen_bits:%d", keySize))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA private key: %v", err)
	}

	// Extract public key
	_, err = h.RunOpenSSL("pkey", "-in", privKeyFile, "-pubout", "-out", pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract RSA public key: %v", err)
	}

	// Read generated files
	privateKeyPEM, err = os.ReadFile(privKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}

	publicKeyPEM, err = os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	return privateKeyPEM, publicKeyPEM, nil
}

// GenerateECDSAWithOpenSSL generates an ECDSA key pair using OpenSSL
func (h *OpenSSLHelper) GenerateECDSAWithOpenSSL(curveName string) (privateKeyPEM, publicKeyPEM []byte, err error) {
	privKeyFile := filepath.Join(h.tempDir, "ecdsa_private.pem")
	pubKeyFile := filepath.Join(h.tempDir, "ecdsa_public.pem")

	// Generate private key
	_, err = h.RunOpenSSL("genpkey", "-algorithm", "EC",
		"-out", privKeyFile, "-pkeyopt", "ec_paramgen_curve:"+curveName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA private key: %v", err)
	}

	// Extract public key
	_, err = h.RunOpenSSL("pkey", "-in", privKeyFile, "-pubout", "-out", pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract ECDSA public key: %v", err)
	}

	// Read generated files
	privateKeyPEM, err = os.ReadFile(privKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}

	publicKeyPEM, err = os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	return privateKeyPEM, publicKeyPEM, nil
}

// GenerateEd25519WithOpenSSL generates an Ed25519 key pair using OpenSSL
func (h *OpenSSLHelper) GenerateEd25519WithOpenSSL() (privateKeyPEM, publicKeyPEM []byte, err error) {
	privKeyFile := filepath.Join(h.tempDir, "ed25519_private.pem")
	pubKeyFile := filepath.Join(h.tempDir, "ed25519_public.pem")

	// Generate private key
	_, err = h.RunOpenSSL("genpkey", "-algorithm", "Ed25519", "-out", privKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 private key: %v", err)
	}

	// Extract public key
	_, err = h.RunOpenSSL("pkey", "-in", privKeyFile, "-pubout", "-out", pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract Ed25519 public key: %v", err)
	}

	// Read generated files
	privateKeyPEM, err = os.ReadFile(privKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}

	publicKeyPEM, err = os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	return privateKeyPEM, publicKeyPEM, nil
}

// ValidatePrivateKeyWithOpenSSL validates a private key using OpenSSL
func (h *OpenSSLHelper) ValidatePrivateKeyWithOpenSSL(privateKeyPEM []byte, algorithm string) error {
	keyFile := h.TempFile("private_key.pem", privateKeyPEM)

	h.t.Logf("    → Validating %s private key with OpenSSL...", strings.ToUpper(algorithm))

	switch strings.ToLower(algorithm) {
	case "rsa":
		_, err := h.RunOpenSSL("rsa", "-in", keyFile, "-check", "-noout")
		if err == nil {
			h.t.Logf("    ✓ RSA private key validation passed")
		}
		return err
	case "ecdsa", "ec":
		_, err := h.RunOpenSSL("ec", "-in", keyFile, "-check", "-noout")
		if err == nil {
			h.t.Logf("    ✓ ECDSA private key validation passed")
		}
		return err
	case "ed25519":
		_, err := h.RunOpenSSL("pkey", "-in", keyFile, "-check", "-noout")
		if err == nil {
			h.t.Logf("    ✓ Ed25519 private key validation passed")
		}
		return err
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// ValidatePublicKeyWithOpenSSL validates a public key using OpenSSL
func (h *OpenSSLHelper) ValidatePublicKeyWithOpenSSL(publicKeyPEM []byte) error {
	keyFile := h.TempFile("public_key.pem", publicKeyPEM)

	h.t.Logf("    → Validating public key with OpenSSL...")
	_, err := h.RunOpenSSL("pkey", "-pubin", "-in", keyFile, "-noout")
	if err == nil {
		h.t.Logf("    ✓ Public key validation passed")
	}
	return err
}

// SignDataWithOpenSSL signs data using OpenSSL
func (h *OpenSSLHelper) SignDataWithOpenSSL(data, privateKeyPEM []byte, algorithm string) ([]byte, error) {
	keyFile := h.TempFile("signing_key.pem", privateKeyPEM)
	dataFile := h.TempFile("data.txt", data)
	sigFile := filepath.Join(h.tempDir, "signature.bin")

	var hashAlg string
	switch strings.ToLower(algorithm) {
	case "rsa":
		hashAlg = "sha256"
	case "ecdsa", "ec":
		hashAlg = "sha256"
	case "ed25519":
		// Ed25519 doesn't use separate hash algorithm
		_, err := h.RunOpenSSL("pkeyutl", "-sign", "-inkey", keyFile, "-in", dataFile, "-out", sigFile)
		if err != nil {
			return nil, err
		}
		return os.ReadFile(sigFile)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	_, err := h.RunOpenSSL("dgst", "-"+hashAlg, "-sign", keyFile, "-out", sigFile, dataFile)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(sigFile)
}

// VerifySignatureWithOpenSSL verifies a signature using OpenSSL
func (h *OpenSSLHelper) VerifySignatureWithOpenSSL(data, signature, publicKeyPEM []byte, algorithm string) error {
	pubKeyFile := h.TempFile("verify_key.pem", publicKeyPEM)
	dataFile := h.TempFile("verify_data.txt", data)
	sigFile := h.TempFile("verify_signature.bin", signature)

	switch strings.ToLower(algorithm) {
	case "rsa", "ecdsa", "ec":
		_, err := h.RunOpenSSL("dgst", "-sha256", "-verify", pubKeyFile, "-signature", sigFile, dataFile)
		return err
	case "ed25519":
		_, err := h.RunOpenSSL("pkeyutl", "-verify", "-pubin", "-inkey", pubKeyFile, "-in", dataFile, "-sigfile", sigFile)
		return err
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// CompareRSAKeys compares RSA keys for mathematical equivalence
func CompareRSAKeys(key1, key2 *rsa.PrivateKey) bool {
	if key1 == nil || key2 == nil {
		return false
	}
	return key1.N.Cmp(key2.N) == 0 && key1.E == key2.E && key1.D.Cmp(key2.D) == 0
}

// CompareECDSAKeys compares ECDSA keys for mathematical equivalence
func CompareECDSAKeys(key1, key2 *ecdsa.PrivateKey) bool {
	if key1 == nil || key2 == nil {
		return false
	}
	return key1.Curve == key2.Curve &&
		key1.X.Cmp(key2.X) == 0 &&
		key1.Y.Cmp(key2.Y) == 0 &&
		key1.D.Cmp(key2.D) == 0
}

// CompareEd25519Keys compares Ed25519 keys for equivalence
func CompareEd25519Keys(key1, key2 ed25519.PrivateKey) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			return false
		}
	}
	return true
}

// ParsePrivateKeyPEM parses a PEM-encoded private key
func ParsePrivateKeyPEM(pemData []byte) (interface{}, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// ParsePublicKeyPEM parses a PEM-encoded public key
func ParsePublicKeyPEM(pemData []byte) (interface{}, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}

// CreateTestData creates test data for signing/verification
func CreateTestData() []byte {
	testString := "This is test data for OpenSSL compatibility testing with GoPKI library"
	hash := sha256.Sum256([]byte(testString))
	return hash[:]
}
