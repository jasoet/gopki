//go:build compatibility

package bao_test

import (
	"crypto/x509"
	"testing"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/pkcs12"
	"github.com/jasoet/gopki/signing"
)

func TestE2E_Bao_Integration(t *testing.T) {
	t.Parallel()

	t.Run("Web_Server_Certificate_Workflow", testWebServerCertificateWorkflow)
	t.Run("Code_Signing_Workflow", testCodeSigningWorkflow)
	t.Run("Email_Protection_Workflow", testEmailProtectionWorkflow)
	t.Run("Mutual_TLS_Workflow", testMutualTLSWorkflow)
	t.Run("Certificate_Renewal_Workflow", testCertificateRenewalWorkflow)
}

// testWebServerCertificateWorkflow tests the complete web server certificate workflow.
func testWebServerCertificateWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	t.Log("=== Web Server Certificate Workflow ===")

	// Step 1: Generate key locally with GoPKI
	t.Log("Step 1: Generate RSA key with GoPKI")
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Create role in Bao
	t.Log("Step 2: Create web-server role in Bao")
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com", "example.org"},
		AllowSubdomains: true,
		TTL:             "720h",
		MaxTTL:          "8760h",
		ServerFlag:      true,
		KeyType:         "rsa",
		KeyBits:         2048,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Step 3: Issue certificate from Bao
	t.Log("Step 3: Issue certificate from Bao")
	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "www.example.com",
		AltNames:   []string{"example.com", "api.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Step 4: Get CA certificate
	t.Log("Step 4: Get CA certificate")
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	// Step 5: Export to PKCS#12 for deployment
	t.Log("Step 5: Export to PKCS#12")
	password := "secure-password"
	pfxData, err := pkcs12.Create(keyPair,certificate.Certificate, []*x509.Certificate{caCert}, password, pkcs12.Options{
		FriendlyName: "Web Server Certificate",
	})
	if err != nil {
		t.Fatalf("Failed to create PKCS#12: %v", err)
	}

	// Step 6: Verify PKCS#12 bundle
	t.Log("Step 6: Verify PKCS#12 bundle")
	parsedKey, parsedCert, parsedCAs, err := pkcs12.Parse(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	if parsedKey == nil {
		t.Fatalf("Private key not in PKCS#12")
	}

	if parsedCert.Certificate.Subject.CommonName != "www.example.com" {
		t.Errorf("Certificate CN mismatch")
	}

	if len(parsedCAs) < 1 {
		t.Errorf("CA certificate not in PKCS#12")
	}

	// Verify certificate extensions
	hasServerAuth := false
	for _, ext := range certificate.Certificate.ExtKeyUsage {
		if ext == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Errorf("Certificate missing ServerAuth extension")
	}

	t.Log("✓ Web Server Certificate Workflow completed successfully")
	t.Logf("  Certificate CN: %s", certificate.Certificate.Subject.CommonName)
	t.Logf("  SANs: %v", certificate.Certificate.DNSNames)
	t.Logf("  Valid until: %s", certificate.Certificate.NotAfter)
}

// testCodeSigningWorkflow tests the code signing certificate workflow.
func testCodeSigningWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	t.Log("=== Code Signing Certificate Workflow ===")

	// Step 1: Generate key with GoPKI
	t.Log("Step 1: Generate ECDSA key with GoPKI")
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Create code signing role
	t.Log("Step 2: Create code-signing role in Bao")
	err = issuer.CreateRole(env.Ctx, "code-signing", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "8760h", // 1 year
		MaxTTL:          "26280h", // 3 years
		CodeSigningFlag: true,
		KeyType:         "ec",
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Step 3: Issue code signing certificate
	t.Log("Step 3: Issue code signing certificate")
	certClient, err := env.Client.IssueECDSACertificate(env.Ctx, "code-signing", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "developer.example.com",
		TTL:        "8760h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Step 4: Sign code with PKCS#7
	t.Log("Step 4: Sign code with PKCS#7")
	codeData := []byte("#!/bin/bash\necho 'Hello World'\n")
	signature, err := signing.Sign(codeData, keyPair, certificate, signing.SignatureOptions{
		Detached: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign code: %v", err)
	}

	// Step 5: Verify signature
	t.Log("Step 5: Verify signature")
	_, err = signing.VerifyDetached(signature, codeData, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	// Verify certificate has code signing extension
	hasCodeSigning := false
	for _, ext := range certificate.Certificate.ExtKeyUsage {
		if ext == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		t.Errorf("Certificate missing CodeSigning extension")
	}

	t.Log("✓ Code Signing Workflow completed successfully")
	t.Logf("  Certificate CN: %s", certificate.Certificate.Subject.CommonName)
	t.Logf("  Signature size: %d bytes", len(signature))
}

// testEmailProtectionWorkflow tests the email protection certificate workflow.
func testEmailProtectionWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	t.Log("=== Email Protection Certificate Workflow ===")

	// Step 1: Generate key
	t.Log("Step 1: Generate RSA key")
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Create email protection role
	t.Log("Step 2: Create email-protection role in Bao")
	err = issuer.CreateRole(env.Ctx, "email-protection", &bao.RoleOptions{
		AllowedDomains:       []string{"example.com"},
		AllowSubdomains:      true,
		TTL:                  "8760h",
		EmailProtectionFlag:  true,
		KeyType:              "rsa",
		KeyBits:              2048,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Step 3: Issue certificate with email
	t.Log("Step 3: Issue email protection certificate")
	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "email-protection", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "user@example.com",
		TTL:        "8760h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Step 4: Sign email content
	t.Log("Step 4: Sign email with S/MIME")
	emailContent := []byte("From: user@example.com\nTo: recipient@example.com\nSubject: Test Email\n\nThis is a test email.")
	signature, err := signing.Sign(emailContent, keyPair, certificate, signing.SignatureOptions{
		Detached: false,
	})
	if err != nil {
		t.Fatalf("Failed to sign email: %v", err)
	}

	// Step 5: Verify signature
	t.Log("Step 5: Verify email signature")
	verifiedContent, err := signing.Verify(signature, signing.VerifyOptions{})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if string(verifiedContent) != string(emailContent) {
		t.Errorf("Verified content doesn't match original")
	}

	// Verify certificate has email protection extension
	hasEmailProtection := false
	for _, ext := range certificate.Certificate.ExtKeyUsage {
		if ext == x509.ExtKeyUsageEmailProtection {
			hasEmailProtection = true
			break
		}
	}
	if !hasEmailProtection {
		t.Errorf("Certificate missing EmailProtection extension")
	}

	t.Log("✓ Email Protection Workflow completed successfully")
	t.Logf("  Certificate CN: %s", certificate.Certificate.Subject.CommonName)
}

// testMutualTLSWorkflow tests the mutual TLS certificate workflow.
func testMutualTLSWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	t.Log("=== Mutual TLS Certificate Workflow ===")

	// Step 1: Create server certificate
	t.Log("Step 1: Create server certificate")
	serverKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	err = issuer.CreateRole(env.Ctx, "tls-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
		ClientFlag:      false,
	})
	if err != nil {
		t.Fatalf("Failed to create server role: %v", err)
	}

	serverCertClient, err := env.Client.IssueRSACertificate(env.Ctx, "tls-server", serverKey, &bao.GenerateCertificateOptions{
		CommonName: "server.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue server certificate: %v", err)
	}

	serverCert, err := serverCertClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get server certificate: %v", err)
	}

	// Step 2: Create client certificate
	t.Log("Step 2: Create client certificate")
	clientKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	err = issuer.CreateRole(env.Ctx, "tls-client", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      false,
		ClientFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create client role: %v", err)
	}

	clientCertClient, err := env.Client.IssueRSACertificate(env.Ctx, "tls-client", clientKey, &bao.GenerateCertificateOptions{
		CommonName: "client.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue client certificate: %v", err)
	}

	clientCert, err := clientCertClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get client certificate: %v", err)
	}

	// Step 3: Get CA certificate
	t.Log("Step 3: Get CA certificate")
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	// Step 4: Verify server certificate
	t.Log("Step 4: Verify certificates")
	ValidateCertificateChain(t, serverCert, caCert)
	ValidateCertificateChain(t, clientCert, caCert)

	// Verify server has ServerAuth
	hasServerAuth := false
	for _, ext := range serverCert.ExtKeyUsage {
		if ext == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Errorf("Server certificate missing ServerAuth extension")
	}

	// Verify client has ClientAuth
	hasClientAuth := false
	for _, ext := range clientCert.ExtKeyUsage {
		if ext == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Errorf("Client certificate missing ClientAuth extension")
	}

	t.Log("✓ Mutual TLS Workflow completed successfully")
	t.Logf("  Server Certificate CN: %s", serverCert.Subject.CommonName)
	t.Logf("  Client Certificate CN: %s", clientCert.Subject.CommonName)
}

// testCertificateRenewalWorkflow tests the certificate renewal workflow.
func testCertificateRenewalWorkflow(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	t.Log("=== Certificate Renewal Workflow ===")

	// Step 1: Generate key (keep the same key for renewal)
	t.Log("Step 1: Generate RSA key")
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Create role
	t.Log("Step 2: Create role")
	err = issuer.CreateRole(env.Ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Step 3: Issue initial certificate
	t.Log("Step 3: Issue initial certificate")
	certClient1, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue initial certificate: %v", err)
	}

	cert1, err := certClient1.Certificate()
	if err != nil {
		t.Fatalf("Failed to get initial certificate: %v", err)
	}

	t.Logf("  Initial certificate serial: %s", cert1.SerialNumber)
	t.Logf("  Initial certificate valid until: %s", cert1.NotAfter)

	// Step 4: Renew certificate (same key, new certificate)
	t.Log("Step 4: Renew certificate")
	certClient2, err := env.Client.IssueRSACertificate(env.Ctx, "web-server", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to renew certificate: %v", err)
	}

	cert2, err := certClient2.Certificate()
	if err != nil {
		t.Fatalf("Failed to get renewed certificate: %v", err)
	}

	t.Logf("  Renewed certificate serial: %s", cert2.SerialNumber)
	t.Logf("  Renewed certificate valid until: %s", cert2.NotAfter)

	// Verify certificates are different but have same CN
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Errorf("Renewed certificate has same serial number")
	}

	if cert1.Subject.CommonName != cert2.Subject.CommonName {
		t.Errorf("Certificate CN changed during renewal")
	}

	// Step 5: Both certificates should be valid
	t.Log("Step 5: Verify both certificates are valid")
	caCert, err := issuer.Certificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	ValidateCertificateChain(t, cert1, caCert)
	ValidateCertificateChain(t, cert2, caCert)

	t.Log("✓ Certificate Renewal Workflow completed successfully")
	t.Log("  Key remained the same, new certificate issued")
}
