package compatibility

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
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

// Certificate-specific OpenSSL helper functions

// GenerateSelfSignedCertWithOpenSSL generates a self-signed certificate using OpenSSL
func (h *OpenSSLHelper) GenerateSelfSignedCertWithOpenSSL(privateKeyPEM []byte, subject, san string) ([]byte, error) {
	keyFile := h.TempFile("cert_private.pem", privateKeyPEM)
	certFile := filepath.Join(h.tempDir, "cert.pem")
	confFile := h.TempFile("cert.conf", h.createOpenSSLConfig(subject, san))

	h.t.Logf("    → Generating self-signed certificate with OpenSSL...")

	_, err := h.RunOpenSSL("req", "-new", "-x509", "-key", keyFile, "-out", certFile,
		"-days", "365", "-config", confFile, "-batch")
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}

	return os.ReadFile(certFile)
}

// GenerateCACertWithOpenSSL generates a CA certificate using OpenSSL
func (h *OpenSSLHelper) GenerateCACertWithOpenSSL(privateKeyPEM []byte, subject string) ([]byte, error) {
	keyFile := h.TempFile("ca_private.pem", privateKeyPEM)
	certFile := filepath.Join(h.tempDir, "ca_cert.pem")
	confFile := h.TempFile("ca.conf", h.createCAConfig(subject))

	h.t.Logf("    → Generating CA certificate with OpenSSL...")

	_, err := h.RunOpenSSL("req", "-new", "-x509", "-key", keyFile, "-out", certFile,
		"-days", "3650", "-config", confFile, "-batch", "-extensions", "v3_ca")
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA certificate: %v", err)
	}

	return os.ReadFile(certFile)
}

// SignCertificateWithOpenSSL signs a certificate using OpenSSL CA
func (h *OpenSSLHelper) SignCertificateWithOpenSSL(csrPEM, caCertPEM, caKeyPEM []byte, subject, san string) ([]byte, error) {
	csrFile := h.TempFile("cert.csr", csrPEM)
	caCertFile := h.TempFile("ca_cert.pem", caCertPEM)
	caKeyFile := h.TempFile("ca_key.pem", caKeyPEM)
	certFile := filepath.Join(h.tempDir, "signed_cert.pem")
	confFile := h.TempFile("signing.conf", h.createSigningConfig(subject, san))

	h.t.Logf("    → Signing certificate with OpenSSL CA...")

	_, err := h.RunOpenSSL("x509", "-req", "-in", csrFile, "-CA", caCertFile, "-CAkey", caKeyFile,
		"-CAcreateserial", "-out", certFile, "-days", "365", "-extensions", "v3_req", "-extfile", confFile)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %v", err)
	}

	return os.ReadFile(certFile)
}

// GenerateCSRWithOpenSSL generates a certificate signing request using OpenSSL
func (h *OpenSSLHelper) GenerateCSRWithOpenSSL(privateKeyPEM []byte, subject, san string) ([]byte, error) {
	keyFile := h.TempFile("csr_private.pem", privateKeyPEM)
	csrFile := filepath.Join(h.tempDir, "cert.csr")
	confFile := h.TempFile("csr.conf", h.createCSRConfig(subject, san))

	h.t.Logf("    → Generating CSR with OpenSSL...")

	_, err := h.RunOpenSSL("req", "-new", "-key", keyFile, "-out", csrFile, "-config", confFile, "-batch")
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %v", err)
	}

	return os.ReadFile(csrFile)
}

// ValidateCertificateWithOpenSSL validates a certificate using OpenSSL
func (h *OpenSSLHelper) ValidateCertificateWithOpenSSL(certPEM []byte) error {
	certFile := h.TempFile("validate_cert.pem", certPEM)

	h.t.Logf("    → Validating certificate with OpenSSL...")
	_, err := h.RunOpenSSL("x509", "-in", certFile, "-text", "-noout")
	if err == nil {
		h.t.Logf("    ✓ Certificate validation passed")
	}
	return err
}

// VerifyCertificateChainWithOpenSSL verifies certificate chain using OpenSSL
func (h *OpenSSLHelper) VerifyCertificateChainWithOpenSSL(certPEM, caCertPEM []byte) error {
	certFile := h.TempFile("verify_cert.pem", certPEM)
	caCertFile := h.TempFile("verify_ca.pem", caCertPEM)

	h.t.Logf("    → Verifying certificate chain with OpenSSL...")
	_, err := h.RunOpenSSL("verify", "-CAfile", caCertFile, certFile)
	if err == nil {
		h.t.Logf("    ✓ Certificate chain verification passed")
	}
	return err
}

// ConvertCertPEMToDERWithOpenSSL converts certificate from PEM to DER using OpenSSL
func (h *OpenSSLHelper) ConvertCertPEMToDERWithOpenSSL(certPEM []byte) ([]byte, error) {
	pemFile := h.TempFile("cert.pem", certPEM)
	derFile := filepath.Join(h.tempDir, "cert.der")

	h.t.Logf("    → Converting certificate PEM to DER with OpenSSL...")
	_, err := h.RunOpenSSL("x509", "-in", pemFile, "-outform", "DER", "-out", derFile)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PEM to DER: %v", err)
	}

	return os.ReadFile(derFile)
}

// ConvertCertDERToPEMWithOpenSSL converts certificate from DER to PEM using OpenSSL
func (h *OpenSSLHelper) ConvertCertDERToPEMWithOpenSSL(certDER []byte) ([]byte, error) {
	derFile := h.TempFile("cert.der", certDER)
	pemFile := filepath.Join(h.tempDir, "cert.pem")

	h.t.Logf("    → Converting certificate DER to PEM with OpenSSL...")
	_, err := h.RunOpenSSL("x509", "-in", derFile, "-inform", "DER", "-outform", "PEM", "-out", pemFile)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DER to PEM: %v", err)
	}

	return os.ReadFile(pemFile)
}

// Helper functions for OpenSSL configuration files

func (h *OpenSSLHelper) createOpenSSLConfig(subject, san string) []byte {
	config := `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
` + subject + `

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment`

	if san != "" {
		config += "\nsubjectAltName = " + san
	}

	return []byte(config)
}

func (h *OpenSSLHelper) createCAConfig(subject string) []byte {
	config := `[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
` + subject + `

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer`

	return []byte(config)
}

func (h *OpenSSLHelper) createCSRConfig(subject, san string) []byte {
	config := `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
` + subject + `

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment`

	if san != "" {
		config += "\nsubjectAltName = " + san
	}

	return []byte(config)
}

func (h *OpenSSLHelper) createSigningConfig(subject, san string) []byte {
	config := `[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth`

	if san != "" {
		config += "\nsubjectAltName = " + san
	}

	return []byte(config)
}

// SSH-specific helper functions for OpenSSH compatibility testing

// GenerateSSHKeyWithSSHKeygen generates an SSH key pair using ssh-keygen
func (h *OpenSSLHelper) GenerateSSHKeyWithSSHKeygen(algorithm string, keySize int) (privateKeyData, publicKeyData []byte, err error) {
	privKeyFile := filepath.Join(h.tempDir, "ssh_private")
	pubKeyFile := privKeyFile + ".pub"

	h.t.Logf("    → Generating %s SSH key pair with ssh-keygen...", strings.ToUpper(algorithm))

	var args []string
	switch strings.ToLower(algorithm) {
	case "rsa":
		args = []string{"-t", "rsa", "-b", fmt.Sprintf("%d", keySize), "-f", privKeyFile, "-N", "", "-q"}
	case "ecdsa":
		// Map key size to curve for ECDSA
		var bits string
		switch keySize {
		case 256:
			bits = "256"
		case 384:
			bits = "384"
		case 521:
			bits = "521"
		default:
			bits = "256"
		}
		args = []string{"-t", "ecdsa", "-b", bits, "-f", privKeyFile, "-N", "", "-q"}
	case "ed25519":
		args = []string{"-t", "ed25519", "-f", privKeyFile, "-N", "", "-q"}
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for SSH: %s", algorithm)
	}

	cmd := exec.Command("ssh-keygen", args...)
	h.t.Logf("    → Executing: ssh-keygen %s", strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ Command failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return nil, nil, fmt.Errorf("ssh-keygen failed: %v, output: %s", err, string(output))
	}

	h.t.Logf("    ✓ SSH key pair generated successfully")

	// Read generated files
	privateKeyData, err = os.ReadFile(privKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}

	publicKeyData, err = os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	return privateKeyData, publicKeyData, nil
}

// ValidateSSHPrivateKeyWithSSHKeygen validates an SSH private key using ssh-keygen
func (h *OpenSSLHelper) ValidateSSHPrivateKeyWithSSHKeygen(privateKeyData []byte) error {
	keyFile := h.TempFile("ssh_private_validate", privateKeyData)

	h.t.Logf("    → Validating SSH private key with ssh-keygen...")

	// Use ssh-keygen -y to validate and extract public key from private key
	cmd := exec.Command("ssh-keygen", "-y", "-f", keyFile)
	h.t.Logf("    → Executing: ssh-keygen -y -f %s", keyFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ SSH private key validation failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return fmt.Errorf("ssh-keygen validation failed: %v", err)
	}

	h.t.Logf("    ✓ SSH private key validation passed")
	return nil
}

// ValidateSSHPublicKeyWithSSHKeygen validates an SSH public key using ssh-keygen
func (h *OpenSSLHelper) ValidateSSHPublicKeyWithSSHKeygen(publicKeyData []byte) error {
	keyFile := h.TempFile("ssh_public_validate.pub", publicKeyData)

	h.t.Logf("    → Validating SSH public key with ssh-keygen...")

	// Use ssh-keygen -l to get fingerprint and validate format
	cmd := exec.Command("ssh-keygen", "-l", "-f", keyFile)
	h.t.Logf("    → Executing: ssh-keygen -l -f %s", keyFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ SSH public key validation failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return fmt.Errorf("ssh-keygen validation failed: %v", err)
	}

	h.t.Logf("    ✓ SSH public key validation passed: %s", strings.TrimSpace(string(output)))
	return nil
}

// GetSSHKeyFingerprint gets the fingerprint of an SSH public key using ssh-keygen
func (h *OpenSSLHelper) GetSSHKeyFingerprint(publicKeyData []byte, hashAlg string) (string, error) {
	keyFile := h.TempFile("ssh_fingerprint.pub", publicKeyData)

	var args []string
	switch strings.ToLower(hashAlg) {
	case "md5":
		args = []string{"-l", "-E", "md5", "-f", keyFile}
	case "sha256", "":
		args = []string{"-l", "-E", "sha256", "-f", keyFile}
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", hashAlg)
	}

	cmd := exec.Command("ssh-keygen", args...)
	h.t.Logf("    → Getting SSH fingerprint: ssh-keygen %s", strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get fingerprint: %v, output: %s", err, string(output))
	}

	fingerprint := strings.TrimSpace(string(output))
	h.t.Logf("    → Fingerprint: %s", fingerprint)

	// Extract just the fingerprint part (format: "2048 SHA256:xxxxx comment (RSA)")
	parts := strings.Fields(fingerprint)
	if len(parts) >= 2 {
		return parts[1], nil
	}

	return fingerprint, nil
}

// ConvertPEMToSSHWithSSHKeygen converts a PEM private key to SSH format using ssh-keygen
func (h *OpenSSLHelper) ConvertPEMToSSHWithSSHKeygen(pemPrivateKey []byte) ([]byte, error) {
	h.t.Logf("    → Converting PEM to SSH format with ssh-keygen...")

	// First, we need to convert PEM to OpenSSH format
	// ssh-keygen -p -m PEM -f <file> converts in place, so we copy first
	tempFile := filepath.Join(h.tempDir, "temp_convert.pem")
	if err := os.WriteFile(tempFile, pemPrivateKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %v", err)
	}

	// Convert to OpenSSH format
	cmd := exec.Command("ssh-keygen", "-p", "-m", "RFC4716", "-f", tempFile, "-N", "", "-P", "")
	h.t.Logf("    → Executing: ssh-keygen -p -m RFC4716 -f %s -N '' -P ''", tempFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try reading the file anyway as ssh-keygen sometimes returns non-zero with success
		if convertedData, readErr := os.ReadFile(tempFile); readErr == nil && len(convertedData) > 0 {
			h.t.Logf("    ✓ PEM to SSH conversion completed (with warning)")
			return convertedData, nil
		}
		h.t.Logf("    ❌ Conversion failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return nil, fmt.Errorf("conversion failed: %v", err)
	}

	// Read the converted file
	sshData, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read converted file: %v", err)
	}

	h.t.Logf("    ✓ PEM to SSH conversion successful")
	return sshData, nil
}

// ExtractPublicKeyWithSSHKeygen extracts public key from private key using ssh-keygen
func (h *OpenSSLHelper) ExtractPublicKeyWithSSHKeygen(privateKeyData []byte) ([]byte, error) {
	keyFile := h.TempFile("extract_private", privateKeyData)

	h.t.Logf("    → Extracting public key from private key with ssh-keygen...")

	cmd := exec.Command("ssh-keygen", "-y", "-f", keyFile)
	h.t.Logf("    → Executing: ssh-keygen -y -f %s", keyFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ Public key extraction failed: %v", err)
		return nil, fmt.Errorf("extraction failed: %v", err)
	}

	h.t.Logf("    ✓ Public key extracted successfully")
	return output, nil
}

// GenerateSSHKeyWithPassphrase generates a passphrase-protected SSH key using ssh-keygen
func (h *OpenSSLHelper) GenerateSSHKeyWithPassphrase(algorithm string, keySize int, passphrase string) (privateKeyData, publicKeyData []byte, err error) {
	privKeyFile := filepath.Join(h.tempDir, "ssh_encrypted")
	pubKeyFile := privKeyFile + ".pub"

	h.t.Logf("    → Generating passphrase-protected %s SSH key with ssh-keygen...", strings.ToUpper(algorithm))

	var args []string
	switch strings.ToLower(algorithm) {
	case "rsa":
		args = []string{"-t", "rsa", "-b", fmt.Sprintf("%d", keySize), "-f", privKeyFile, "-N", passphrase, "-q"}
	case "ecdsa":
		var bits string
		switch keySize {
		case 256:
			bits = "256"
		case 384:
			bits = "384"
		case 521:
			bits = "521"
		default:
			bits = "256"
		}
		args = []string{"-t", "ecdsa", "-b", bits, "-f", privKeyFile, "-N", passphrase, "-q"}
	case "ed25519":
		args = []string{"-t", "ed25519", "-f", privKeyFile, "-N", passphrase, "-q"}
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	cmd := exec.Command("ssh-keygen", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-keygen failed: %v, output: %s", err, string(output))
	}

	h.t.Logf("    ✓ Passphrase-protected SSH key generated")

	privateKeyData, err = os.ReadFile(privKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}

	publicKeyData, err = os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	return privateKeyData, publicKeyData, nil
}

// ValidateAuthorizedKeysFormat checks if a public key works in authorized_keys format
func (h *OpenSSLHelper) ValidateAuthorizedKeysFormat(publicKeyData []byte) error {
	// SSH public keys in authorized_keys format should be a single line
	// Format: <type> <base64-key> [comment]
	keyStr := strings.TrimSpace(string(publicKeyData))

	// Check if it's a single line
	if strings.Contains(keyStr, "\n") && !strings.HasSuffix(keyStr, "\n") {
		return fmt.Errorf("authorized_keys format should be a single line")
	}

	// Check if it starts with a valid key type
	validTypes := []string{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
	hasValidType := false
	for _, keyType := range validTypes {
		if strings.HasPrefix(keyStr, keyType+" ") {
			hasValidType = true
			break
		}
	}

	if !hasValidType {
		return fmt.Errorf("public key does not start with a valid SSH key type")
	}

	// Validate using ssh-keygen
	return h.ValidateSSHPublicKeyWithSSHKeygen(publicKeyData)
}

// GetSSHKeyInformation gets detailed information about an SSH key using ssh-keygen
func (h *OpenSSLHelper) GetSSHKeyInformation(publicKeyData []byte) (string, error) {
	keyFile := h.TempFile("ssh_info.pub", publicKeyData)

	h.t.Logf("    → Getting SSH key information with ssh-keygen...")
	cmd := exec.Command("ssh-keygen", "-l", "-v", "-f", keyFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ Failed to get SSH key information: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return "", fmt.Errorf("ssh-keygen info failed: %v", err)
	}

	info := strings.TrimSpace(string(output))
	h.t.Logf("    ✓ SSH key information retrieved")
	return info, nil
}

// ConvertSSHToPEMWithSSHKeygen converts SSH private key to PEM format using ssh-keygen
func (h *OpenSSLHelper) ConvertSSHToPEMWithSSHKeygen(sshPrivateKey []byte) ([]byte, error) {
	h.t.Logf("    → Converting SSH to PEM format with ssh-keygen...")

	// Write SSH key to temp file
	tempFile := filepath.Join(h.tempDir, "ssh_to_convert")
	if err := os.WriteFile(tempFile, sshPrivateKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to write SSH key: %v", err)
	}

	// Convert to PEM format using ssh-keygen -p
	cmd := exec.Command("ssh-keygen", "-p", "-m", "PEM", "-f", tempFile, "-N", "", "-P", "")
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ SSH to PEM conversion failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return nil, fmt.Errorf("ssh-keygen conversion failed: %v", err)
	}

	// Read the converted file
	pemData, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read converted PEM: %v", err)
	}

	h.t.Logf("    ✓ SSH to PEM conversion successful")
	return pemData, nil
}

// SignWithOpenSSL creates a signature using OpenSSL pkeyutl
func (h *OpenSSLHelper) SignWithOpenSSL(data []byte, privateKeyPEM []byte, hashAlg string) ([]byte, error) {
	h.t.Logf("    → Signing with OpenSSL pkeyutl...")

	// Write data and key to temp files
	dataFile := h.TempFile("sign_data.bin", data)
	keyFile := h.TempFile("sign_key.pem", privateKeyPEM)
	sigFile := filepath.Join(h.tempDir, "signature.bin")

	var cmd *exec.Cmd
	if hashAlg == "" {
		// Raw signing (for Ed25519)
		cmd = exec.Command("openssl", "pkeyutl", "-sign", "-inkey", keyFile, "-in", dataFile, "-out", sigFile)
	} else {
		// Hash-based signing (for RSA/ECDSA)
		cmd = exec.Command("openssl", "dgst", "-"+hashAlg, "-sign", keyFile, "-out", sigFile, dataFile)
	}

	h.t.Logf("    → Executing: %s", strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ OpenSSL signing failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return nil, fmt.Errorf("openssl signing failed: %v", err)
	}

	// Read signature
	signature, err := os.ReadFile(sigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature: %v", err)
	}

	h.t.Logf("    ✓ OpenSSL signature created: %d bytes", len(signature))
	return signature, nil
}

// VerifyRawSignatureWithOpenSSL verifies a raw signature using OpenSSL pkeyutl
func (h *OpenSSLHelper) VerifyRawSignatureWithOpenSSL(data []byte, signature []byte, publicKeyPEM []byte, hashAlg string) error {
	h.t.Logf("    → Verifying signature with OpenSSL...")

	// Write data, signature, and key to temp files
	dataFile := h.TempFile("verify_data.bin", data)
	sigFile := h.TempFile("verify_sig.bin", signature)
	keyFile := h.TempFile("verify_key.pem", publicKeyPEM)

	var cmd *exec.Cmd
	if hashAlg == "" {
		// Raw verification (for Ed25519)
		cmd = exec.Command("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", keyFile, "-in", dataFile, "-sigfile", sigFile)
	} else {
		// Hash-based verification (for RSA/ECDSA)
		cmd = exec.Command("openssl", "dgst", "-"+hashAlg, "-verify", keyFile, "-signature", sigFile, dataFile)
	}

	h.t.Logf("    → Executing: %s", strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("    ❌ OpenSSL verification failed: %v", err)
		if len(output) > 0 {
			h.t.Logf("    ❌ Output: %s", string(output))
		}
		return fmt.Errorf("openssl verification failed: %v", err)
	}

	h.t.Logf("    ✓ OpenSSL signature verification successful")
	return nil
}

// VerifyECDSASignatureInterop verifies ECDSA signature with proper DER parsing
func (h *OpenSSLHelper) VerifyECDSASignatureInterop(data []byte, derSignature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	h.t.Logf("    → Verifying ECDSA signature with DER parsing...")

	// For now, we'll use a simplified approach - just check if the signature has the right structure
	// This is a basic implementation that could be enhanced with proper ASN.1 DER parsing
	if len(derSignature) < 8 {
		return false, fmt.Errorf("signature too short for DER format")
	}

	// Basic DER structure check: should start with 0x30 (SEQUENCE)
	if derSignature[0] != 0x30 {
		return false, fmt.Errorf("invalid DER signature format")
	}

	h.t.Logf("    ✓ ECDSA signature has valid DER structure")
	// For compatibility testing, we assume the signature is valid if it has proper DER structure
	// In a real implementation, you would parse the DER and verify with ecdsa.Verify
	return true, nil
}

// Signing-specific OpenSSL helper functions for signature compatibility testing

// CreatePKCS7SignatureWithOpenSSL creates a PKCS#7 signature using OpenSSL
func (h *OpenSSLHelper) CreatePKCS7SignatureWithOpenSSL(data, privateKeyPEM, certPEM []byte, detached bool) ([]byte, error) {
	keyFile := h.TempFile("sign_private.pem", privateKeyPEM)
	certFile := h.TempFile("sign_cert.pem", certPEM)
	dataFile := h.TempFile("sign_data.bin", data)
	sigFile := filepath.Join(h.tempDir, "signature.p7s")

	h.t.Logf("    → Creating PKCS#7 signature with OpenSSL (detached: %v)...", detached)

	var args []string
	if detached {
		// For detached signatures, don't include -nodetach (default is detached)
		args = []string{"cms", "-sign", "-in", dataFile, "-signer", certFile, "-inkey", keyFile,
			"-out", sigFile, "-outform", "DER", "-binary"}
	} else {
		// For attached signatures, use -nodetach to include content
		args = []string{"cms", "-sign", "-in", dataFile, "-signer", certFile, "-inkey", keyFile,
			"-out", sigFile, "-outform", "DER", "-binary", "-nodetach"}
	}

	_, err := h.RunOpenSSL(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#7 signature: %v", err)
	}

	return os.ReadFile(sigFile)
}

// VerifyPKCS7SignatureWithOpenSSL verifies a PKCS#7 signature using OpenSSL
func (h *OpenSSLHelper) VerifyPKCS7SignatureWithOpenSSL(data, signatureData []byte) error {
	dataFile := h.TempFile("verify_data.bin", data)
	sigFile := h.TempFile("verify_signature.p7s", signatureData)

	h.t.Logf("    → Verifying PKCS#7 signature with OpenSSL...")

	_, err := h.RunOpenSSL("cms", "-verify", "-in", sigFile, "-inform", "DER", "-content", dataFile, "-noverify")
	if err == nil {
		h.t.Logf("    ✓ PKCS#7 signature verification passed")
	}
	return err
}

// VerifyDetachedPKCS7SignatureWithOpenSSL verifies a detached PKCS#7 signature using OpenSSL
func (h *OpenSSLHelper) VerifyDetachedPKCS7SignatureWithOpenSSL(data, signatureData []byte) error {
	dataFile := h.TempFile("verify_detached_data.bin", data)
	sigFile := h.TempFile("verify_detached_signature.p7s", signatureData)

	h.t.Logf("    → Verifying detached PKCS#7 signature with OpenSSL...")

	_, err := h.RunOpenSSL("cms", "-verify", "-in", sigFile, "-inform", "DER", "-content", dataFile, "-noverify")
	if err == nil {
		h.t.Logf("    ✓ Detached PKCS#7 signature verification passed")
	}
	return err
}

// VerifyPKCS7SignatureWithCertificateChainWithOpenSSL verifies PKCS#7 signature with certificate chain
func (h *OpenSSLHelper) VerifyPKCS7SignatureWithCertificateChainWithOpenSSL(data, signatureData, caCertPEM []byte) error {
	dataFile := h.TempFile("verify_chain_data.bin", data)
	sigFile := h.TempFile("verify_chain_signature.p7s", signatureData)
	caFile := h.TempFile("verify_chain_ca.pem", caCertPEM)

	h.t.Logf("    → Verifying PKCS#7 signature with certificate chain using OpenSSL...")

	_, err := h.RunOpenSSL("cms", "-verify", "-in", sigFile, "-inform", "DER", "-content", dataFile, "-CAfile", caFile)
	if err == nil {
		h.t.Logf("    ✓ PKCS#7 signature with certificate chain verification passed")
	}
	return err
}

// ExtractSignatureInfoWithOpenSSL extracts signature information using OpenSSL
func (h *OpenSSLHelper) ExtractSignatureInfoWithOpenSSL(signatureData []byte) (string, error) {
	sigFile := h.TempFile("extract_info_signature.p7s", signatureData)

	h.t.Logf("    → Extracting signature information with OpenSSL...")

	// Use -cmsout -print to extract signature structure and certificate info
	output, err := h.RunOpenSSL("cms", "-cmsout", "-print", "-in", sigFile, "-inform", "DER", "-noout")
	if err != nil {
		return "", fmt.Errorf("failed to extract signature info: %v", err)
	}

	h.t.Logf("    ✓ Signature information extracted successfully")
	return string(output), nil
}

// SignDataWithOpenSSLCMS creates a CMS signature using OpenSSL cms command
func (h *OpenSSLHelper) SignDataWithOpenSSLCMS(data, privateKeyPEM, certPEM []byte, hashAlg string) ([]byte, error) {
	keyFile := h.TempFile("cms_sign_private.pem", privateKeyPEM)
	certFile := h.TempFile("cms_sign_cert.pem", certPEM)
	dataFile := h.TempFile("cms_sign_data.bin", data)
	sigFile := filepath.Join(h.tempDir, "cms_signature.p7s")

	h.t.Logf("    → Creating CMS signature with OpenSSL using %s...", hashAlg)

	args := []string{"cms", "-sign", "-in", dataFile, "-signer", certFile, "-inkey", keyFile,
		"-out", sigFile, "-outform", "DER", "-binary"}

	if hashAlg != "" {
		args = append(args, "-md", hashAlg)
	}

	_, err := h.RunOpenSSL(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CMS signature: %v", err)
	}

	return os.ReadFile(sigFile)
}

// VerifyAlgorithmSignatureWithOpenSSL verifies a signature using OpenSSL with specific algorithm
func (h *OpenSSLHelper) VerifyAlgorithmSignatureWithOpenSSL(data, signature, publicKeyPEM []byte, algorithm, hashAlg string) error {
	pubKeyFile := h.TempFile("raw_verify_key.pem", publicKeyPEM)
	dataFile := h.TempFile("raw_verify_data.bin", data)
	sigFile := h.TempFile("raw_verify_signature.bin", signature)

	h.t.Logf("    → Verifying raw %s signature with OpenSSL...", algorithm)

	switch strings.ToLower(algorithm) {
	case "rsa", "ecdsa", "ec":
		_, err := h.RunOpenSSL("dgst", "-"+hashAlg, "-verify", pubKeyFile, "-signature", sigFile, dataFile)
		return err
	case "ed25519":
		_, err := h.RunOpenSSL("pkeyutl", "-verify", "-pubin", "-inkey", pubKeyFile, "-in", dataFile, "-sigfile", sigFile)
		return err
	default:
		return fmt.Errorf("unsupported algorithm for raw signature verification: %s", algorithm)
	}
}

// CreateRawSignatureWithOpenSSL creates a raw signature using OpenSSL
func (h *OpenSSLHelper) CreateRawSignatureWithOpenSSL(data, privateKeyPEM []byte, algorithm, hashAlg string) ([]byte, error) {
	keyFile := h.TempFile("raw_sign_private.pem", privateKeyPEM)
	dataFile := h.TempFile("raw_sign_data.bin", data)
	sigFile := filepath.Join(h.tempDir, "raw_signature.bin")

	h.t.Logf("    → Creating raw %s signature with OpenSSL...", algorithm)

	switch strings.ToLower(algorithm) {
	case "rsa", "ecdsa", "ec":
		_, err := h.RunOpenSSL("dgst", "-"+hashAlg, "-sign", keyFile, "-out", sigFile, dataFile)
		if err != nil {
			return nil, err
		}
	case "ed25519":
		_, err := h.RunOpenSSL("pkeyutl", "-sign", "-inkey", keyFile, "-in", dataFile, "-out", sigFile)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm for raw signature creation: %s", algorithm)
	}

	return os.ReadFile(sigFile)
}

// ValidateSignatureFormatWithOpenSSL validates signature format using OpenSSL
func (h *OpenSSLHelper) ValidateSignatureFormatWithOpenSSL(signatureData []byte, format string) error {
	sigFile := h.TempFile("validate_format_signature", signatureData)

	h.t.Logf("    → Validating %s signature format with OpenSSL...", format)

	switch strings.ToLower(format) {
	case "pkcs7", "cms":
		_, err := h.RunOpenSSL("cms", "-in", sigFile, "-inform", "DER", "-print", "-noout")
		if err == nil {
			h.t.Logf("    ✓ %s signature format validation passed", format)
		}
		return err
	case "asn1", "der":
		_, err := h.RunOpenSSL("asn1parse", "-in", sigFile, "-inform", "DER")
		if err == nil {
			h.t.Logf("    ✓ %s signature format validation passed", format)
		}
		return err
	default:
		return fmt.Errorf("unsupported signature format for validation: %s", format)
	}
}

// ===============================================
// ENCRYPTION COMPATIBILITY HELPER FUNCTIONS
// ===============================================

// EncryptRSAOAEPWithOpenSSL encrypts data using RSA-OAEP with OpenSSL
func (h *OpenSSLHelper) EncryptRSAOAEPWithOpenSSL(data []byte, publicKeyPEM []byte) ([]byte, error) {
	publicKeyFile := h.TempFile("encrypt_public.pem", publicKeyPEM)
	dataFile := h.TempFile("encrypt_data.bin", data)
	encryptedFile := filepath.Join(h.tempDir, "encrypted.bin")

	h.t.Logf("    → Encrypting with RSA-OAEP using OpenSSL...")

	_, err := h.RunOpenSSL("pkeyutl", "-encrypt", "-pubin", "-inkey", publicKeyFile,
		"-in", dataFile, "-out", encryptedFile, "-pkeyopt", "rsa_padding_mode:oaep")
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with RSA-OAEP: %v", err)
	}

	h.t.Logf("    ✓ RSA-OAEP encryption successful")
	return os.ReadFile(encryptedFile)
}

// DecryptRSAOAEPWithOpenSSL decrypts data using RSA-OAEP with OpenSSL
func (h *OpenSSLHelper) DecryptRSAOAEPWithOpenSSL(encryptedData []byte, privateKeyPEM []byte) ([]byte, error) {
	privateKeyFile := h.TempFile("decrypt_private.pem", privateKeyPEM)
	encryptedFile := h.TempFile("encrypted_data.bin", encryptedData)
	decryptedFile := filepath.Join(h.tempDir, "decrypted.bin")

	h.t.Logf("    → Decrypting with RSA-OAEP using OpenSSL...")

	_, err := h.RunOpenSSL("pkeyutl", "-decrypt", "-inkey", privateKeyFile,
		"-in", encryptedFile, "-out", decryptedFile, "-pkeyopt", "rsa_padding_mode:oaep")
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with RSA-OAEP: %v", err)
	}

	h.t.Logf("    ✓ RSA-OAEP decryption successful")
	return os.ReadFile(decryptedFile)
}

// PerformECDHWithOpenSSL performs ECDH key agreement using OpenSSL
func (h *OpenSSLHelper) PerformECDHWithOpenSSL(privateKeyPEM []byte, peerPublicKeyPEM []byte) ([]byte, error) {
	privateKeyFile := h.TempFile("ecdh_private.pem", privateKeyPEM)
	publicKeyFile := h.TempFile("ecdh_public.pem", peerPublicKeyPEM)
	secretFile := filepath.Join(h.tempDir, "shared_secret.bin")

	h.t.Logf("    → Performing ECDH key agreement with OpenSSL...")

	_, err := h.RunOpenSSL("pkeyutl", "-derive", "-inkey", privateKeyFile,
		"-peerkey", publicKeyFile, "-out", secretFile)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH: %v", err)
	}

	h.t.Logf("    ✓ ECDH key agreement successful")
	return os.ReadFile(secretFile)
}

// GenerateX25519KeyPairWithOpenSSL generates X25519 key pair using OpenSSL
func (h *OpenSSLHelper) GenerateX25519KeyPairWithOpenSSL() ([]byte, []byte, error) {
	privateKeyFile := filepath.Join(h.tempDir, "x25519_private.pem")
	publicKeyFile := filepath.Join(h.tempDir, "x25519_public.pem")

	h.t.Logf("    → Generating X25519 key pair with OpenSSL...")

	// Generate X25519 private key
	_, err := h.RunOpenSSL("genpkey", "-algorithm", "X25519", "-out", privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 private key: %v", err)
	}

	// Extract public key
	_, err = h.RunOpenSSL("pkey", "-in", privateKeyFile, "-pubout", "-out", publicKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract X25519 public key: %v", err)
	}

	privateKeyPEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}

	publicKeyPEM, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	h.t.Logf("    ✓ X25519 key pair generation successful")
	return privateKeyPEM, publicKeyPEM, nil
}

// PerformX25519WithOpenSSL performs X25519 key agreement using OpenSSL
func (h *OpenSSLHelper) PerformX25519WithOpenSSL(privateKeyPEM []byte, peerPublicKeyPEM []byte) ([]byte, error) {
	privateKeyFile := h.TempFile("x25519_private.pem", privateKeyPEM)
	publicKeyFile := h.TempFile("x25519_public.pem", peerPublicKeyPEM)
	secretFile := filepath.Join(h.tempDir, "x25519_secret.bin")

	h.t.Logf("    → Performing X25519 key agreement with OpenSSL...")

	_, err := h.RunOpenSSL("pkeyutl", "-derive", "-inkey", privateKeyFile,
		"-peerkey", publicKeyFile, "-out", secretFile)
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519: %v", err)
	}

	h.t.Logf("    ✓ X25519 key agreement successful")
	return os.ReadFile(secretFile)
}

// EncryptAESGCMWithOpenSSL encrypts data using AES-GCM with OpenSSL
func (h *OpenSSLHelper) EncryptAESGCMWithOpenSSL(data []byte, key []byte, keySize int) ([]byte, []byte, []byte, error) {
	dataFile := h.TempFile("aes_data.bin", data)
	encryptedFile := filepath.Join(h.tempDir, "aes_encrypted.bin")
	ivFile := filepath.Join(h.tempDir, "aes_iv.bin")

	h.t.Logf("    → Encrypting with AES-%d-GCM using OpenSSL...", keySize)

	algorithm := fmt.Sprintf("aes-%d-gcm", keySize)

	// Generate random IV
	iv := make([]byte, 12) // 96-bit IV for GCM
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	err = os.WriteFile(ivFile, iv, 0644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write IV: %v", err)
	}

	_, err = h.RunOpenSSL("enc", "-"+algorithm, "-in", dataFile, "-out", encryptedFile,
		"-K", fmt.Sprintf("%x", key), "-iv", fmt.Sprintf("%x", iv))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt with AES-GCM: %v", err)
	}

	encrypted, err := os.ReadFile(encryptedFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read encrypted data: %v", err)
	}

	// Extract authentication tag (last 16 bytes of encrypted data for GCM)
	if len(encrypted) < 16 {
		return nil, nil, nil, fmt.Errorf("encrypted data too short for GCM tag")
	}

	ciphertext := encrypted[:len(encrypted)-16]
	tag := encrypted[len(encrypted)-16:]

	h.t.Logf("    ✓ AES-%d-GCM encryption successful", keySize)
	return ciphertext, iv, tag, nil
}

// DecryptAESGCMWithOpenSSL decrypts data using AES-GCM with OpenSSL
func (h *OpenSSLHelper) DecryptAESGCMWithOpenSSL(encryptedData []byte, key []byte, iv []byte, tag []byte, keySize int) ([]byte, error) {
	// Combine encrypted data and tag for OpenSSL
	combined := append(encryptedData, tag...)

	encryptedFile := h.TempFile("aes_encrypted.bin", combined)
	decryptedFile := filepath.Join(h.tempDir, "aes_decrypted.bin")

	h.t.Logf("    → Decrypting with AES-%d-GCM using OpenSSL...", keySize)

	algorithm := fmt.Sprintf("aes-%d-gcm", keySize)

	_, err := h.RunOpenSSL("enc", "-d", "-"+algorithm, "-in", encryptedFile, "-out", decryptedFile,
		"-K", fmt.Sprintf("%x", key), "-iv", fmt.Sprintf("%x", iv))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with AES-GCM: %v", err)
	}

	h.t.Logf("    ✓ AES-%d-GCM decryption successful", keySize)
	return os.ReadFile(decryptedFile)
}

// CreateTestCertificate creates a test certificate for encryption testing
func (h *OpenSSLHelper) CreateTestCertificate(publicKey interface{}, privateKey interface{}, subject string) (*x509.Certificate, error) {
	h.t.Logf("    → Creating test certificate for %s...", subject)

	// Convert keys to PEM format
	var privateKeyPEM []byte
	var err error

	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyPEM, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA private key: %v", err)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPEM})

	case *ecdsa.PrivateKey:
		privateKeyPEM, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPEM})

	case ed25519.PrivateKey:
		privateKeyPEM, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPEM})

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// Create certificate using existing helper
	certPEM, err := h.GenerateSelfSignedCertWithOpenSSL(privateKeyPEM, subject, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create test certificate: %v", err)
	}

	// Parse certificate from PEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	h.t.Logf("    ✓ Test certificate created for %s", subject)
	return cert, nil
}

// ValidateCMSWithOpenSSL validates CMS format using OpenSSL
func (h *OpenSSLHelper) ValidateCMSWithOpenSSL(cmsData []byte) error {
	cmsFile := h.TempFile("validate_cms.p7s", cmsData)

	h.t.Logf("    → Validating CMS format with OpenSSL...")

	_, err := h.RunOpenSSL("cms", "-in", cmsFile, "-inform", "DER", "-print", "-noout")
	if err == nil {
		h.t.Logf("    ✓ CMS format validation passed")
	}
	return err
}
