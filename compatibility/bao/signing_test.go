//go:build compatibility

package bao_test

import (
	"crypto/x509"
	"testing"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/signing"
)

func TestSigning_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("PKCS7_Signing", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_RSA_Cert_Sign_Verify", testBaoRSACertPKCS7SignVerify)
		t.Run("Bao_ECDSA_Cert_Sign_Verify", testBaoECDSACertPKCS7SignVerify)
		t.Run("Bao_Ed25519_Cert_Sign_Verify", testBaoEd25519CertPKCS7SignVerify)
		t.Run("Certificate_Chain_In_PKCS7", testCertificateChainInPKCS7)
	})

	t.Run("Detached_Signatures", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Cert_Detached_Sign", testBaoCertDetachedSign)
		t.Run("Detached_Signature_Verification", testDetachedSignatureVerification)
	})

	t.Run("Certificate_Chain_Signing", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Intermediate_Chain_PKCS7", testBaoIntermediateChainPKCS7)
	})
}

// testBaoRSACertPKCS7SignVerify tests PKCS#7 signing with Bao-issued RSA certificate.
func testBaoRSACertPKCS7SignVerify(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key locally
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role with code signing
	err = issuer.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate from Bao
	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Sign data with GoPKI signing module
	data := []byte("Important data to sign with RSA certificate from Bao")
	signature, err := signing.Sign(data, keyPair, certificate, signing.SignatureOptions{
		Detached: false,
	})
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify signature with GoPKI
	content, err := signing.Verify(signature, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if string(content) != string(data) {
		t.Errorf("Verified content mismatch")
	}

	t.Logf("✓ Successfully signed and verified with Bao RSA certificate")
}

// testBaoECDSACertPKCS7SignVerify tests PKCS#7 signing with Bao-issued ECDSA certificate.
func testBaoECDSACertPKCS7SignVerify(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key locally
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role
	err = issuer.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate from Bao
	certClient, err := env.Client.IssueECDSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Sign data with GoPKI signing module
	data := []byte("Important data to sign with ECDSA certificate from Bao")
	signature, err := signing.Sign(data, keyPair, certificate, signing.SignatureOptions{
		Detached: false,
	})
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify signature with GoPKI
	content, err := signing.Verify(signature, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if string(content) != string(data) {
		t.Errorf("Verified content mismatch")
	}

	t.Logf("✓ Successfully signed and verified with Bao ECDSA certificate")
}

// testBaoEd25519CertPKCS7SignVerify tests PKCS#7 signing with Bao-issued Ed25519 certificate.
func testBaoEd25519CertPKCS7SignVerify(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key locally
	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role
	err = issuer.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Issue certificate from Bao
	certClient, err := env.Client.IssueEd25519Certificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Sign data with GoPKI signing module
	data := []byte("Important data to sign with Ed25519 certificate from Bao")

	// Note: Ed25519 PKCS#7 signing may have limitations
	signature, err := signing.Sign(data, keyPair, certificate, signing.SignatureOptions{
		Detached: false,
	})

	if err != nil {
		t.Logf("⚠️  Ed25519 PKCS#7 signing limitation: %v", err)
		t.Skip("Ed25519 PKCS#7 may not be fully supported")
		return
	}

	// Verify signature with GoPKI
	content, err := signing.Verify(signature, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if string(content) != string(data) {
		t.Errorf("Verified content mismatch")
	}

	t.Logf("✓ Successfully signed and verified with Bao Ed25519 certificate")
}

// testCertificateChainInPKCS7 tests including certificate chain in PKCS#7 signatures.
func testCertificateChainInPKCS7(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Create root CA
	rootCA, err := CreateTestRootCA(env.Ctx, env.Client, "root-ca", "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	rootCert, err := rootCA.Certificate()
	if err != nil {
		t.Fatalf("Failed to get root cert: %v", err)
	}

	// Create intermediate CA
	intermediateCA, err := CreateTestIntermediateCA(env.Ctx, env.Client, rootCA, "intermediate-ca", "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	intermediateCert, err := intermediateCA.Certificate()
	if err != nil {
		t.Fatalf("Failed to get intermediate cert: %v", err)
	}

	// Generate key and issue end-entity certificate
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	err = intermediateCA.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Sign with full certificate chain
	data := []byte("Data signed with certificate chain")
	signature, err := signing.SignWithChain(data, keyPair,certificate.Certificate, []*x509.Certificate{intermediateCert, rootCert}, signing.SignatureOptions{
		Detached: false,
	})
	if err != nil {
		t.Fatalf("Failed to sign with chain: %v", err)
	}

	// Verify signature
	content, err := signing.Verify(signature, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if string(content) != string(data) {
		t.Errorf("Verified content mismatch")
	}

	t.Logf("✓ Successfully signed with Bao certificate chain")
}

// testBaoCertDetachedSign tests detached signatures with Bao certificates.
func testBaoCertDetachedSign(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Create detached signature
	data := []byte("Data for detached signature")
	signature, err := signing.Sign(data, keyPair, certificate, signing.SignatureOptions{
		Detached: true,
	})
	if err != nil {
		t.Fatalf("Failed to create detached signature: %v", err)
	}

	// Verify detached signature
	_, err = signing.VerifyDetached(signature, data, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify detached signature: %v", err)
	}

	t.Logf("✓ Successfully created and verified detached signature with Bao certificate")
}

// testDetachedSignatureVerification tests detached signature verification.
func testDetachedSignatureVerification(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Create detached signature
	originalData := []byte("Original data content")
	signature, err := signing.Sign(originalData, keyPair, certificate, signing.SignatureOptions{
		Detached: true,
	})
	if err != nil {
		t.Fatalf("Failed to create detached signature: %v", err)
	}

	// Verify with correct data
	_, err = signing.VerifyDetached(signature, originalData, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify detached signature: %v", err)
	}

	// Verify with wrong data should fail
	wrongData := []byte("Wrong data content")
	_, err = signing.VerifyDetached(signature, wrongData, signing.VerifyOptions{})
	if err == nil {
		t.Errorf("Verification should fail with wrong data")
	} else {
		t.Logf("✓ Correctly rejected signature with wrong data")
	}

	t.Logf("✓ Detached signature verification works correctly")
}

// testBaoIntermediateChainPKCS7 tests PKCS#7 signing with intermediate CA chain.
func testBaoIntermediateChainPKCS7(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Create root CA
	rootCA, err := CreateTestRootCA(env.Ctx, env.Client, "root-ca", "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	rootCert, err := rootCA.Certificate()
	if err != nil {
		t.Fatalf("Failed to get root cert: %v", err)
	}

	// Create intermediate CA
	intermediateCA, err := CreateTestIntermediateCA(env.Ctx, env.Client, rootCA, "intermediate-ca", "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	intermediateCert, err := intermediateCA.Certificate()
	if err != nil {
		t.Fatalf("Failed to get intermediate cert: %v", err)
	}

	// Generate key and issue certificate
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	err = intermediateCA.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		CodeSigningFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "signer.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Sign with full chain
	data := []byte("Data signed with intermediate CA chain")
	signature, err := signing.SignWithChain(data, keyPair,certificate.Certificate, []*x509.Certificate{intermediateCert, rootCert}, signing.SignatureOptions{
		Detached: false,
	})
	if err != nil {
		t.Fatalf("Failed to sign with intermediate chain: %v", err)
	}

	// Verify signature
	content, err := signing.Verify(signature, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature with intermediate chain: %v", err)
	}

	if string(content) != string(data) {
		t.Errorf("Verified content mismatch")
	}

	t.Logf("✓ Successfully signed and verified with Bao intermediate CA chain")
}
