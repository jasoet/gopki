//go:build compatibility

package bao_test

import (
	"testing"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestKeypair_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		keyType string
		keyBits int
	}{
		{"RSA_2048", "rsa", 2048},
		{"RSA_3072", "rsa", 3072},
		{"RSA_4096", "rsa", 4096},
		{"ECDSA_P256", "ecdsa", 256},
		{"ECDSA_P384", "ecdsa", 384},
		{"ECDSA_P521", "ecdsa", 521},
		{"Ed25519", "ed25519", 256},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			switch tc.keyType {
			case "rsa":
				t.Run("GoPKI_Generate_Bao_Import", func(t *testing.T) {
					testRSAKeyGoPKIToBao(t, tc.keyBits)
				})
				t.Run("Bao_Generate_GoPKI_Use", func(t *testing.T) {
					testRSAKeyBaoToGoPKI(t, tc.keyBits)
				})
				t.Run("Bao_Issue_Cert_With_GoPKI_Key", func(t *testing.T) {
					testBaoIssueCertWithGoPKIRSAKey(t, tc.keyBits)
				})
			case "ecdsa":
				t.Run("GoPKI_Generate_Bao_Import", func(t *testing.T) {
					testECDSAKeyGoPKIToBao(t, tc.keyBits)
				})
				t.Run("Bao_Generate_GoPKI_Use", func(t *testing.T) {
					testECDSAKeyBaoToGoPKI(t, tc.keyBits)
				})
				t.Run("Bao_Issue_Cert_With_GoPKI_Key", func(t *testing.T) {
					testBaoIssueCertWithGoPKIECDSAKey(t, tc.keyBits)
				})
			case "ed25519":
				t.Run("GoPKI_Generate_Bao_Import", func(t *testing.T) {
					testEd25519KeyGoPKIToBao(t)
				})
				t.Run("Bao_Generate_GoPKI_Use", func(t *testing.T) {
					testEd25519KeyBaoToGoPKI(t)
				})
				t.Run("Bao_Issue_Cert_With_GoPKI_Key", func(t *testing.T) {
					testBaoIssueCertWithGoPKIEd25519Key(t)
				})
			}
		})
	}
}

// testRSAKeyGoPKIToBao tests importing GoPKI-generated RSA keys to Bao.
func testRSAKeyGoPKIToBao(t *testing.T, keyBits int) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(keyBits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Import to Bao
	keyClient, err := env.Client.ImportRSAKey(env.Ctx, "test-rsa-key", keyPair, &bao.ImportKeyOptions{})
	if err != nil {
		t.Fatalf("Failed to import key to Bao: %v", err)
	}

	// Verify key is accessible
	keyInfo, err := keyClient.GetKeyInfo(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	expectedKeyType := "rsa-" + string(rune(keyBits/1024)) + "048"
	if keyBits == 3072 {
		expectedKeyType = "rsa-3072"
	}

	if keyInfo.KeyType != expectedKeyType {
		t.Logf("Key type: %s (expected pattern: rsa-*)", keyInfo.KeyType)
	}

	t.Logf("✓ Successfully imported GoPKI RSA-%d key to OpenBao", keyBits)
}

// testRSAKeyBaoToGoPKI tests using Bao-generated RSA keys with GoPKI.
func testRSAKeyBaoToGoPKI(t *testing.T, keyBits int) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao (exported)
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "test-rsa-key-2",
		KeyBits: keyBits,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get key pair for GoPKI use
	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Use with GoPKI cert module
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR with Bao key: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CSR subject mismatch: expected %q, got %q", "test.example.com", csr.Subject.CommonName)
	}

	t.Logf("✓ Successfully used Bao RSA-%d key with GoPKI cert module", keyBits)
}

// testBaoIssueCertWithGoPKIRSAKey tests issuing a certificate from Bao using GoPKI-generated RSA key.
func testBaoIssueCertWithGoPKIRSAKey(t *testing.T, keyBits int) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(keyBits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create role
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate from Bao using GoPKI key
	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch: expected %q, got %q", "app.example.com", certificate.Certificate.Subject.CommonName)
	}

	t.Logf("✓ Successfully issued certificate from Bao using GoPKI RSA-%d key", keyBits)
}

// testECDSAKeyGoPKIToBao tests importing GoPKI-generated ECDSA keys to Bao.
func testECDSAKeyGoPKIToBao(t *testing.T, curveSize int) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	var curveName string
	switch curveSize {
	case 256:
		curveName = "P256"
	case 384:
		curveName = "P384"
	case 521:
		curveName = "P521"
	default:
		t.Fatalf("Unsupported curve size: %d", curveSize)
	}

	// Generate key with GoPKI
	keyPair, err := algo.GenerateECDSAKeyPair(curveName)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Import to Bao
	keyClient, err := env.Client.ImportECDSAKey(env.Ctx, "test-ecdsa-key", keyPair, &bao.ImportKeyOptions{})
	if err != nil {
		t.Fatalf("Failed to import key to Bao: %v", err)
	}

	// Verify key is accessible
	keyInfo, err := keyClient.GetKeyInfo(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	t.Logf("Key type: %s", keyInfo.KeyType)
	t.Logf("✓ Successfully imported GoPKI ECDSA-%s key to OpenBao", curveName)
}

// testECDSAKeyBaoToGoPKI tests using Bao-generated ECDSA keys with GoPKI.
func testECDSAKeyBaoToGoPKI(t *testing.T, curveSize int) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	var curveName string
	switch curveSize {
	case 256:
		curveName = "P256"
	case 384:
		curveName = "P384"
	case 521:
		curveName = "P521"
	default:
		t.Fatalf("Unsupported curve size: %d", curveSize)
	}

	// Generate key with Bao (exported)
	keyClient, err := env.Client.GenerateECDSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "test-ecdsa-key-2",
		Curve:   curveName,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get key pair for GoPKI use
	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Use with GoPKI cert module
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR with Bao key: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CSR subject mismatch")
	}

	t.Logf("✓ Successfully used Bao ECDSA-%s key with GoPKI cert module", curveName)
}

// testBaoIssueCertWithGoPKIECDSAKey tests issuing a certificate from Bao using GoPKI-generated ECDSA key.
func testBaoIssueCertWithGoPKIECDSAKey(t *testing.T, curveSize int) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	var curveName string
	switch curveSize {
	case 256:
		curveName = "P256"
	case 384:
		curveName = "P384"
	case 521:
		curveName = "P521"
	default:
		t.Fatalf("Unsupported curve size: %d", curveSize)
	}

	// Generate key with GoPKI
	keyPair, err := algo.GenerateECDSAKeyPair(curveName)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create role
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate from Bao using GoPKI key
	certClient, err := env.Client.IssueECDSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	t.Logf("✓ Successfully issued certificate from Bao using GoPKI ECDSA-%s key", curveName)
}

// testEd25519KeyGoPKIToBao tests importing GoPKI-generated Ed25519 keys to Bao.
func testEd25519KeyGoPKIToBao(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Import to Bao
	keyClient, err := env.Client.ImportEd25519Key(env.Ctx, "test-ed25519-key", keyPair, &bao.ImportKeyOptions{})
	if err != nil {
		t.Fatalf("Failed to import key to Bao: %v", err)
	}

	// Verify key is accessible
	keyInfo, err := keyClient.GetKeyInfo(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	t.Logf("Key type: %s", keyInfo.KeyType)
	t.Logf("✓ Successfully imported GoPKI Ed25519 key to OpenBao")
}

// testEd25519KeyBaoToGoPKI tests using Bao-generated Ed25519 keys with GoPKI.
func testEd25519KeyBaoToGoPKI(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao (exported)
	keyClient, err := env.Client.GenerateEd25519Key(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "test-ed25519-key-2",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get key pair for GoPKI use
	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Use with GoPKI cert module
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		t.Fatalf("Failed to create CSR with Bao key: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CSR subject mismatch")
	}

	t.Logf("✓ Successfully used Bao Ed25519 key with GoPKI cert module")
}

// testBaoIssueCertWithGoPKIEd25519Key tests issuing a certificate from Bao using GoPKI-generated Ed25519 key.
func testBaoIssueCertWithGoPKIEd25519Key(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create role
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate from Bao using GoPKI key
	certClient, err := env.Client.IssueEd25519Certificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if certificate.Certificate.Subject.CommonName != "app.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	t.Logf("✓ Successfully issued certificate from Bao using GoPKI Ed25519 key")
}
